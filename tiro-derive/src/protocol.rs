use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, Item, Token, Type, braced,
    parse::{Parse, ParseStream},
    token,
};

// Define custom keywords for the protocol macro
mod kw {
    syn::custom_keyword!(statement);
    syn::custom_keyword!(interaction);
    syn::custom_keyword!(message);
    syn::custom_keyword!(challenge);
}

/// Represents either an inline struct definition or a reference to an external type
pub(crate) enum TypeDefinition {
    Inline(Item),
    External(Type),
}

impl Parse for TypeDefinition {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(token::Brace) {
            // Inline definition: { struct Foo { ... } }
            let content;
            braced!(content in input);
            let item = content.parse::<Item>()?;
            Ok(TypeDefinition::Inline(item))
        } else if lookahead.peek(Token![:]) {
            // External reference: : TypeName
            input.parse::<Token![:]>()?;
            let ty = input.parse::<Type>()?;
            input.parse::<Token![,]>()?;
            Ok(TypeDefinition::External(ty))
        } else {
            Err(lookahead.error())
        }
    }
}

/// Represents a single interaction round in the protocol
pub(crate) struct InteractionDef {
    pub(crate) name: Ident,
    pub(crate) message: TypeDefinition,
    pub(crate) challenge: TypeDefinition,
}

impl Parse for InteractionDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        input.parse::<kw::interaction>()?;
        let name = input.parse::<Ident>()?;

        let content;
        braced!(content in input);

        // Parse message
        content.parse::<kw::message>()?;
        let message = content.parse::<TypeDefinition>()?;

        // Parse challenge
        content.parse::<kw::challenge>()?;
        let challenge = content.parse::<TypeDefinition>()?;

        Ok(InteractionDef {
            name,
            message,
            challenge,
        })
    }
}

/// Represents the full protocol definition
pub(crate) struct ProtocolDef {
    pub(crate) protocol_name: Ident,
    pub(crate) statement: TypeDefinition,
    pub(crate) interactions: Vec<InteractionDef>,
}

impl Parse for ProtocolDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let protocol_name = input.parse::<Ident>()?;
        input.parse::<Token![,]>()?;

        // Parse statement
        if input.peek(kw::statement) {
            input.parse::<kw::statement>()?;
        } else {
            return Err(syn::Error::new(
                input.span(),
                "expected 'statement' block after protocol name. Usage: define_protocol! { ProtocolName, statement { ... }, ... }",
            ));
        }
        let statement = input.parse::<TypeDefinition>()?;
        // Optional comma after statement
        let _ = input.parse::<Token![,]>();

        // Parse interactions
        let mut interactions = Vec::new();
        while !input.is_empty() {
            if input.peek(kw::interaction) {
                interactions.push(input.parse::<InteractionDef>()?);
                // Optional comma after interaction
                let _ = input.parse::<Token![,]>();
            } else {
                return Err(syn::Error::new(
                    input.span(),
                    "expected 'interaction' block. Usage: interaction RoundName { message { ... } challenge { ... } }",
                ));
            }
        }

        if interactions.is_empty() {
            return Err(syn::Error::new(
                protocol_name.span(),
                "protocol must have at least one interaction round",
            ));
        }

        Ok(ProtocolDef {
            protocol_name,
            statement,
            interactions,
        })
    }
}

/// Extracts the type name from a TypeDefinition
fn extract_type_name(def: &TypeDefinition) -> Ident {
    match def {
        TypeDefinition::Inline(Item::Struct(s)) => s.ident.clone(),
        TypeDefinition::External(Type::Path(p)) => p.path.segments.last().unwrap().ident.clone(),
        _ => panic!("Unsupported type definition"),
    }
}

/// Generates the struct definition if inline, otherwise returns nothing
fn generate_struct_def(def: &TypeDefinition) -> Option<proc_macro2::TokenStream> {
    match def {
        TypeDefinition::Inline(item) => Some(quote! { #item }),
        TypeDefinition::External(_) => None,
    }
}

/// Generate the implementation for a protocol definition
pub fn generate_protocol_impl(
    protocol_def: ProtocolDef,
    crate_prefix: proc_macro2::TokenStream,
) -> TokenStream {
    let protocol_name = &protocol_def.protocol_name;
    let protocol_name_str = protocol_name.to_string();
    let statement_name = extract_type_name(&protocol_def.statement);

    // Generate struct definitions for inline types
    let mut struct_defs = Vec::new();
    if let Some(def) = generate_struct_def(&protocol_def.statement) {
        struct_defs.push(def);
    }
    for interaction in &protocol_def.interactions {
        if let Some(def) = generate_struct_def(&interaction.message) {
            struct_defs.push(def);
        }
        if let Some(def) = generate_struct_def(&interaction.challenge) {
            struct_defs.push(def);
        }
    }

    // Generate protocol marker types
    let mut marker_types = Vec::new();
    for interaction in &protocol_def.interactions {
        let name = &interaction.name;
        marker_types.push(quote! {
            struct #name;
        });
    }

    // Generate protocol struct and ProtocolStart impl
    let first_interaction = &protocol_def.interactions[0];
    let first_name = &first_interaction.name;
    let protocol_struct = quote! {
        struct #protocol_name;
    };
    let protocol_start_impl = quote! {
        impl #crate_prefix::Protocol for #protocol_name {
            const NAME: &str = #protocol_name_str;
            type Statement = #statement_name;
            type First = #first_name;
        }
    };

    // Generate Interaction impls
    let mut interaction_impls = Vec::new();
    for (i, interaction) in protocol_def.interactions.iter().enumerate() {
        let name = &interaction.name;
        let message_name = extract_type_name(&interaction.message);
        let challenge_name = extract_type_name(&interaction.challenge);

        let next_type = if i + 1 < protocol_def.interactions.len() {
            let next_name = &protocol_def.interactions[i + 1].name;
            quote! { #next_name }
        } else {
            quote! { #crate_prefix::ProtocolEnd }
        };

        interaction_impls.push(quote! {
            impl #crate_prefix::Interaction for #name {
                type Message = #message_name;
                type Challenge = #challenge_name;
                type Next = #next_type;
            }
        });
    }

    // Generate the complete output
    let expanded = quote! {
        #(#struct_defs)*

        #protocol_struct

        #(#marker_types)*

        #protocol_start_impl

        #(#interaction_impls)*
    };

    TokenStream::from(expanded)
}
