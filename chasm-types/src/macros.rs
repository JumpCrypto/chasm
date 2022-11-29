
macro_rules! enumerated_enum {
    ( $(#[$outer_meta:meta])* 
      $Name:ident : $( $(#[$inner_meta:meta])* $Variant:ident = $i:literal,)*) => {
        #[repr(u8)]
        #[derive(Copy, Clone, Debug, ::serde::Deserialize, Eq, Ord, PartialEq, PartialOrd, ::serde::Serialize, schemars::JsonSchema, Default)]
        $(#[$outer_meta])*
        pub enum $Name {
        $(
            $(#[$inner_meta])*
            $Variant = $i,
        )*
        }

        impl core::fmt::Display for $Name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
                core::fmt::Debug::fmt(self, f)
            }
        }

        impl TryFrom<u8> for $Name {
            type Error = Code;
            fn try_from(byte: u8) -> core::result::Result<Self, Self::Error> {
                Self::try_from(byte as i32)
            }
        }

        impl TryFrom<i32> for $Name {
            type Error = Code;
            fn try_from(proto_code: i32) -> core::result::Result<Self, Self::Error> {
                Ok(match proto_code {
                $(
                    $i => $Name::$Variant,
                )*
                    code => return Err(Code::$Name(code)),
                })
            }
        }
    }
}

