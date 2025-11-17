use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, Data, DeriveInput, Field, Fields, GenericParam, Generics, Ident,
    WherePredicate,
};

/// Prefix for generated type parameters to avoid collisions
const SIZE_PARAM_PREFIX: &str = "__FBR_Size";
const SUM_PARAM_PREFIX: &str = "__FBR_Sum";

/// Returns the appropriate crate identifier for the `tiro` crate.
/// Uses `crate` if we're deriving within the tiro crate itself,
/// otherwise uses the actual crate name from Cargo.toml.
fn crate_ident() -> proc_macro2::TokenStream {
    let crate_name = proc_macro_crate::crate_name("tiro").expect("tiro is in Cargo.toml");
    match crate_name {
        proc_macro_crate::FoundCrate::Itself => quote!(crate),
        proc_macro_crate::FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(#ident)
        }
    }
}

/// Extracts fields from a struct, ensuring it's a valid target for the derive macro.
fn extract_fields<'a>(data: &'a Data, struct_name: &Ident) -> Vec<&'a Field> {
    match data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => named.named.iter().collect(),
            Fields::Unnamed(unnamed) => unnamed.unnamed.iter().collect(),
            Fields::Unit => abort!(struct_name, "FromByteRepr cannot be derived for unit structs"),
        },
        _ => abort!(struct_name, "FromByteRepr can only be derived for structs"),
    }
}

/// Generates fresh type parameter identifiers for field sizes.
fn generate_size_idents(field_count: usize) -> Vec<Ident> {
    (0..field_count)
        .map(|i| format_ident!("{}{}", SIZE_PARAM_PREFIX, i))
        .collect()
}

/// Generates fresh type parameter identifiers for suffix sums.
/// For N fields, we only need N-1 sum variables.
fn generate_sum_idents(field_count: usize) -> Vec<Ident> {
    (0..field_count.saturating_sub(1))
        .map(|i| format_ident!("{}{}", SUM_PARAM_PREFIX, i))
        .collect()
}

/// Builds where-clause predicates for the FromByteRepr implementation.
///
/// For n fields, generates:
/// 1. Field type bounds: `T_i: FromByteRepr<Size = Size_i>`
/// 2. Size constraints: `Size_i: ArraySize`
/// 3. Sum relationships: Addition and subtraction constraints between sizes and sums
///    - For N fields, we have N-1 sum variables
///    - Sum_i = Size_i + Sum_{i+1} for i in 0..(N-2)
///    - Sum_{N-2} = Size_{N-2} + Size_{N-1} (last sum uses last size directly)
fn build_where_predicates(
    fields: &[&Field],
    size_idents: &[Ident],
    sum_idents: &[Ident],
) -> Vec<WherePredicate> {
    let mut predicates = Vec::new();
    let field_count = fields.len();

    // Field type bounds: T_i: FromByteRepr<Size = Size_i>
    for (field, size_ident) in fields.iter().zip(size_idents.iter()) {
        let ty = &field.ty;
        predicates.push(syn::parse_quote! {
            #ty: FromByteRepr<Size = #size_ident>
        });
    }

    // All size parameters must be ArraySize
    for size_ident in size_idents.iter() {
        predicates.push(syn::parse_quote! {
            #size_ident: ::hybrid_array::ArraySize
        });
    }

    // Build suffix sum constraints
    // For N fields, we have N-1 sums (sum_idents has length N-1)
    // For k in 0..(N-2): Sum_k = Size_k + Sum_{k+1}
    // For k = N-2 (last sum): Sum_{N-2} = Size_{N-2} + Size_{N-1}

    if field_count >= 2 {
        // Handle all sums except the last one
        for k in 0..(sum_idents.len().saturating_sub(1)) {
            let size_k = &size_idents[k];
            let sum_k = &sum_idents[k];
            let sum_k_plus_1 = &sum_idents[k + 1];

            predicates.push(syn::parse_quote! {
                #size_k: ::hybrid_array::ArraySize + ::core::ops::Add<#sum_k_plus_1, Output = #sum_k>
            });

            predicates.push(syn::parse_quote! {
                #sum_k: ::hybrid_array::ArraySize + ::core::ops::Sub<#size_k, Output = #sum_k_plus_1>
            });
        }

        // Handle the last sum: Sum_{N-2} = Size_{N-2} + Size_{N-1}
        if !sum_idents.is_empty() {
            let last_sum_idx = sum_idents.len() - 1;
            let last_sum = &sum_idents[last_sum_idx];
            let second_to_last_size = &size_idents[last_sum_idx];
            let last_size = &size_idents[field_count - 1];

            predicates.push(syn::parse_quote! {
                #second_to_last_size: ::hybrid_array::ArraySize + ::core::ops::Add<#last_size, Output = #last_sum>
            });

            predicates.push(syn::parse_quote! {
                #last_sum: ::hybrid_array::ArraySize + ::core::ops::Sub<#second_to_last_size, Output = #last_size>
            });
        }
    }

    predicates
}

/// Extends generics with additional type parameters and where-clause predicates.
fn build_impl_generics(
    original_generics: &Generics,
    size_idents: &[Ident],
    sum_idents: &[Ident],
    where_predicates: Vec<WherePredicate>,
) -> Generics {
    let mut impl_generics = original_generics.clone();

    // Add generated type parameters
    for ident in size_idents.iter().chain(sum_idents.iter()) {
        impl_generics.params.push(GenericParam::Type(syn::TypeParam {
            attrs: vec![],
            ident: ident.clone(),
            colon_token: None,
            bounds: syn::punctuated::Punctuated::new(),
            eq_token: None,
            default: None,
        }));
    }

    // Add where-clause predicates
    let where_clause = impl_generics.make_where_clause();
    where_clause.predicates.extend(where_predicates);

    impl_generics
}

/// Constructs the self-type with original generic parameters.
fn build_self_type(name: &Ident, generics: &Generics) -> proc_macro2::TokenStream {
    let params: Vec<_> = generics
        .params
        .iter()
        .map(|p| match p {
            GenericParam::Type(ty) => {
                let ident = &ty.ident;
                quote! { #ident }
            }
            GenericParam::Lifetime(lt) => {
                let lifetime = &lt.lifetime;
                quote! { #lifetime }
            }
            GenericParam::Const(c) => {
                let ident = &c.ident;
                quote! { #ident }
            }
        })
        .collect();

    if params.is_empty() {
        quote! { #name }
    } else {
        quote! { #name<#(#params),*> }
    }
}

/// Generates the statements for the `from_bytes` function body.
///
/// Creates a series of `Array::split_ref` calls to extract byte slices for each field,
/// followed by `FromByteRepr::from_bytes` calls to deserialize each field.
/// For the last field, we use the remaining bytes directly without splitting.
fn generate_from_bytes_body<'a>(
    fields: &[&'a Field],
    size_idents: &[Ident],
    crate_prefix: &proc_macro2::TokenStream,
) -> (Vec<proc_macro2::TokenStream>, Vec<(Ident, &'a Field)>) {
    let mut statements = Vec::new();
    let mut field_values = Vec::new();
    let field_count = fields.len();

    for (i, (field, size_ident)) in fields.iter().zip(size_idents.iter()).enumerate() {
        let bytes_ident = format_ident!("__fbr_bytes{}", i);
        let value_ident = format_ident!("__fbr_val{}", i);
        let ty = &field.ty;

        // For the last field, use remaining bytes directly without splitting
        if i == field_count - 1 {
            if i == 0 {
                // Only one field - use the input bytes directly
                statements.push(quote! {
                    let #value_ident = <#ty as #crate_prefix::FromByteRepr>::from_bytes(bytes);
                });
            } else {
                // Multiple fields - use the remaining bytes from previous split
                let prev_rest = format_ident!("__fbr_rest{}", i - 1);
                statements.push(quote! {
                    let #value_ident = <#ty as #crate_prefix::FromByteRepr>::from_bytes(#prev_rest);
                });
            }
        } else {
            // Not the last field - split off this field's bytes
            let rest_ident = format_ident!("__fbr_rest{}", i);

            if i == 0 {
                statements.push(quote! {
                    let (#bytes_ident, #rest_ident) =
                        ::hybrid_array::Array::split_ref::<#size_ident>(bytes);
                });
            } else {
                let prev_rest = format_ident!("__fbr_rest{}", i - 1);
                statements.push(quote! {
                    let (#bytes_ident, #rest_ident) =
                        ::hybrid_array::Array::split_ref::<#size_ident>(#prev_rest);
                });
            }

            statements.push(quote! {
                let #value_ident = <#ty as #crate_prefix::FromByteRepr>::from_bytes(#bytes_ident);
            });
        }

        field_values.push((value_ident, *field));
    }

    (statements, field_values)
}

/// Constructs the struct value from deserialized field values.
fn generate_struct_construction(
    fields: &Fields,
    field_values: &[(Ident, &Field)],
) -> proc_macro2::TokenStream {
    match fields {
        Fields::Named(_) => {
            let field_assignments: Vec<_> = field_values
                .iter()
                .map(|(value_ident, field)| {
                    let field_name = field.ident.as_ref().expect("named field has ident");
                    quote! { #field_name: #value_ident }
                })
                .collect();
            quote! { Self { #(#field_assignments),* } }
        }
        Fields::Unnamed(_) => {
            let values: Vec<_> = field_values.iter().map(|(v, _)| quote! { #v }).collect();
            quote! { Self(#(#values),*) }
        }
        Fields::Unit => unreachable!("unit structs filtered in extract_fields"),
    }
}

/// Derive macro for `FromByteRepr`.
///
/// This macro implements the `FromByteRepr` trait for structs, enabling deserialization
/// from a fixed-size byte array. The macro handles both named and unnamed struct fields,
/// generating the necessary type-level arithmetic for combining field sizes.
#[proc_macro_error]
#[proc_macro_derive(FromByteRepr)]
pub fn derive_from_byte_repr(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let original_generics = &input.generics;
    let crate_prefix = crate_ident();

    // Extract and validate fields
    let fields = extract_fields(&input.data, struct_name);
    if fields.is_empty() {
        abort!(
            struct_name,
            "FromByteRepr cannot be derived for structs with zero fields"
        );
    }

    // Generate type parameters for sizes and suffix sums
    let field_count = fields.len();
    let size_idents = generate_size_idents(field_count);
    let sum_idents = generate_sum_idents(field_count);

    // Build where-clause predicates
    let where_predicates = build_where_predicates(&fields, &size_idents, &sum_idents);

    // Build implementation generics with added type parameters
    let impl_generics = build_impl_generics(
        original_generics,
        &size_idents,
        &sum_idents,
        where_predicates,
    );

    // Split generics for implementation
    let (impl_generics_tokens, _, where_clause) = impl_generics.split_for_impl();
    let self_type = build_self_type(struct_name, original_generics);

    // Generate the from_bytes function body
    let (body_statements, field_values) =
        generate_from_bytes_body(&fields, &size_idents, &crate_prefix);

    // Get fields information for construction
    let fields_def = match &input.data {
        Data::Struct(s) => &s.fields,
        _ => unreachable!("non-struct filtered in extract_fields"),
    };
    let construction = generate_struct_construction(fields_def, &field_values);

    // The total size depends on the number of fields:
    // - For 1 field: total size = Size_0 (no sum variables)
    // - For N >= 2 fields: total size = Sum_0 (first sum variable)
    let total_size_ident = if field_count == 1 {
        &size_idents[0]
    } else {
        &sum_idents[0]
    };

    // Generate the final implementation
    let expanded = quote! {
        impl #impl_generics_tokens #crate_prefix::FromByteRepr for #self_type #where_clause {
            type Size = #total_size_ident;

            fn from_bytes(bytes: &::hybrid_array::Array<u8, Self::Size>) -> Self {
                #(#body_statements)*
                #construction
            }
        }
    };

    TokenStream::from(expanded)
}

/// Generates `FromByteRepr` implementations for tuples of sizes n through m.
///
/// This macro accepts either a single number or a range expression and generates
/// implementations for the specified tuple sizes.
///
/// # Examples
///
/// ```ignore
/// // Generate implementation for tuple of size 3
/// impl_tuple!(3);
///
/// // Generate implementations for tuples of size 2, 3, and 4
/// impl_tuple!(2..5);
///
/// // Generate implementations for tuples of size 2, 3, 4, and 5 (inclusive)
/// impl_tuple!(2..=5);
/// ```
#[proc_macro]
pub fn impl_tuple(input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let input_str = input_str.trim();

    // Parse input: single number or range expression (n..m or n..=m)
    let (start, end, inclusive) = if let Some((start_str, end_str)) = input_str.split_once("..=") {
        let start: usize = start_str.trim().parse().expect("invalid start value");
        let end: usize = end_str.trim().parse().expect("invalid end value");
        (start, end, true)
    } else if let Some((start_str, end_str)) = input_str.split_once("..") {
        let start: usize = start_str.trim().parse().expect("invalid start value");
        let end: usize = end_str.trim().parse().expect("invalid end value");
        (start, end, false)
    } else {
        // Single number - generate implementation for just that size
        let size: usize = input_str.parse().expect("Expected a number or range expression like '3', '2..5', or '2..=5'");
        (size, size, true)
    };

    let crate_prefix = crate_ident();
    let mut implementations = Vec::new();

    let range_end = if inclusive { end + 1 } else { end };

    for tuple_size in start..range_end {
        if tuple_size == 0 {
            continue; // Skip empty tuple
        }

        let impl_tokens = generate_tuple_impl(tuple_size, &crate_prefix);
        implementations.push(impl_tokens);
    }

    let expanded = quote! {
        #(#implementations)*
    };

    TokenStream::from(expanded)
}

/// Generates a single `FromByteRepr` implementation for a tuple of the given size.
fn generate_tuple_impl(
    tuple_size: usize,
    crate_prefix: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    // Generate type parameter identifiers for tuple elements
    let type_params: Vec<Ident> = (0..tuple_size)
        .map(|i| format_ident!("T{}", i))
        .collect();

    // Generate size and sum identifiers (reusing existing functions)
    let size_idents = generate_size_idents(tuple_size);
    let sum_idents = generate_sum_idents(tuple_size);

    // Build where-clause predicates for tuple elements
    let mut where_predicates: Vec<WherePredicate> = Vec::new();

    // Type bounds: T_i: FromByteRepr<Size = Size_i>
    for (type_param, size_ident) in type_params.iter().zip(size_idents.iter()) {
        where_predicates.push(syn::parse_quote! {
            #type_param: #crate_prefix::FromByteRepr<Size = #size_ident>
        });
    }

    // All size parameters must be ArraySize
    for size_ident in size_idents.iter() {
        where_predicates.push(syn::parse_quote! {
            #size_ident: ::hybrid_array::ArraySize
        });
    }

    // Build suffix sum constraints (same logic as struct derive)
    if tuple_size >= 2 {
        // Handle all sums except the last one
        for k in 0..(sum_idents.len().saturating_sub(1)) {
            let size_k = &size_idents[k];
            let sum_k = &sum_idents[k];
            let sum_k_plus_1 = &sum_idents[k + 1];

            where_predicates.push(syn::parse_quote! {
                #size_k: ::hybrid_array::ArraySize + ::core::ops::Add<#sum_k_plus_1, Output = #sum_k>
            });

            where_predicates.push(syn::parse_quote! {
                #sum_k: ::hybrid_array::ArraySize + ::core::ops::Sub<#size_k, Output = #sum_k_plus_1>
            });
        }

        // Handle the last sum
        if !sum_idents.is_empty() {
            let last_sum_idx = sum_idents.len() - 1;
            let last_sum = &sum_idents[last_sum_idx];
            let second_to_last_size = &size_idents[last_sum_idx];
            let last_size = &size_idents[tuple_size - 1];

            where_predicates.push(syn::parse_quote! {
                #second_to_last_size: ::hybrid_array::ArraySize + ::core::ops::Add<#last_size, Output = #last_sum>
            });

            where_predicates.push(syn::parse_quote! {
                #last_sum: ::hybrid_array::ArraySize + ::core::ops::Sub<#second_to_last_size, Output = #last_size>
            });
        }
    }

    // Generate the from_bytes function body for tuples
    let mut body_statements = Vec::new();
    let mut value_idents = Vec::new();

    for (i, (type_param, size_ident)) in type_params.iter().zip(size_idents.iter()).enumerate() {
        let bytes_ident = format_ident!("__fbr_bytes{}", i);
        let value_ident = format_ident!("__fbr_val{}", i);

        // For the last element, use remaining bytes directly without splitting
        if i == tuple_size - 1 {
            if i == 0 {
                // Only one element - use the input bytes directly
                body_statements.push(quote! {
                    let #value_ident = <#type_param as #crate_prefix::FromByteRepr>::from_bytes(bytes);
                });
            } else {
                // Multiple elements - use the remaining bytes from previous split
                let prev_rest = format_ident!("__fbr_rest{}", i - 1);
                body_statements.push(quote! {
                    let #value_ident = <#type_param as #crate_prefix::FromByteRepr>::from_bytes(#prev_rest);
                });
            }
        } else {
            // Not the last element - split off this element's bytes
            let rest_ident = format_ident!("__fbr_rest{}", i);

            if i == 0 {
                body_statements.push(quote! {
                    let (#bytes_ident, #rest_ident) =
                        ::hybrid_array::Array::split_ref::<#size_ident>(bytes);
                });
            } else {
                let prev_rest = format_ident!("__fbr_rest{}", i - 1);
                body_statements.push(quote! {
                    let (#bytes_ident, #rest_ident) =
                        ::hybrid_array::Array::split_ref::<#size_ident>(#prev_rest);
                });
            }

            body_statements.push(quote! {
                let #value_ident = <#type_param as #crate_prefix::FromByteRepr>::from_bytes(#bytes_ident);
            });
        }

        value_idents.push(value_ident);
    }

    // The total size depends on the number of elements
    let total_size_ident = if tuple_size == 1 {
        &size_idents[0]
    } else {
        &sum_idents[0]
    };

    // Build the tuple type and construction
    let tuple_type = if tuple_size == 1 {
        let t0 = &type_params[0];
        quote! { (#t0,) }
    } else {
        quote! { (#(#type_params),*) }
    };

    let tuple_construction = if tuple_size == 1 {
        let v0 = &value_idents[0];
        quote! { (#v0,) }
    } else {
        quote! { (#(#value_idents),*) }
    };

    // Collect all generic parameters: type params + size params + sum params
    let all_generics = type_params.iter()
        .chain(size_idents.iter())
        .chain(sum_idents.iter());

    quote! {
        impl<#(#all_generics),*> #crate_prefix::FromByteRepr for #tuple_type
        where
            #(#where_predicates),*
        {
            type Size = #total_size_ident;

            fn from_bytes(bytes: &::hybrid_array::Array<u8, Self::Size>) -> Self {
                #(#body_statements)*
                #tuple_construction
            }
        }
    }
}
