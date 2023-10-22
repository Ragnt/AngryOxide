use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod inner;

/// A little helper derive macro to implement the `libwifi::Addresses` trait
/// for frames with either a DataHeader or a ManagementHeader.
///
/// This macro is only designed for internal usage in the [libwifi](https://docs.rs/libwifi/latest/libwifi/) crate.
///
/// How to use:
/// ```rust,ignore
/// #[derive(Clone, Debug, AddressHeader)]
/// pub struct AssociationRequest {
///     pub header: ManagementHeader,
///     pub beacon_interval: u16,
///     pub capability_info: u16,
///     pub station_info: StationInfo,
/// }
/// ```
///
/// The new generated code will look like this:
/// ```rust,ignore
/// impl crate::Addresses for AssociationRequest {
///     fn src(&self) -> Option<&MacAddress> {
///         self.header.src()
///     }
///
///     fn dest(&self) -> &MacAddress {
///         self.header.dest()
///     }
///
///     fn bssid(&self) -> Option<&MacAddress> {
///         self.header.bssid()
///     }
/// }
/// ```
#[proc_macro_derive(AddressHeader)]
pub fn address_header(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let toks = inner::address_header_inner(&input).unwrap_or_else(|err| err.to_compile_error());

    toks.into()
}
