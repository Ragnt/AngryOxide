use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

pub fn address_header_inner(ast: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;

    Ok(quote! {
        impl crate::Addresses for #name {
            fn src(&self) -> Option<&MacAddress> {
                self.header.src()
            }

            fn dest(&self) -> &MacAddress {
                self.header.dest()
            }

            fn bssid(&self) -> Option<&MacAddress> {
                self.header.bssid()
            }
        }
    })
}
