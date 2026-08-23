//! RFC 3454 preparation primitives pinned to Unicode 3.2 semantics.

use alloc::string::String;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{PreparationError, SecretString};

mod unicode32_bidi;

pub(crate) fn prepare_query(
    value: &str,
    error: PreparationError,
) -> Result<String, PreparationError> {
    let prepared = prepare_sasl(value).map_err(|()| error)?;
    Ok(String::from(prepared.as_str()))
}

pub(crate) fn prepare_stored(value: &str) -> Result<SecretString, PreparationError> {
    if value.chars().any(stringprep::tables::unassigned_code_point) {
        return Err(PreparationError::InvalidPassword);
    }
    let prepared = prepare_sasl(value).map_err(|()| PreparationError::InvalidPassword)?;
    Ok(SecretString::new(prepared.as_str()))
}

fn prepare_sasl(value: &str) -> Result<Zeroizing<String>, ()> {
    let mapped = value
        .chars()
        .map(|character| {
            if stringprep::tables::non_ascii_space_character(character) {
                ' '
            } else {
                character
            }
        })
        .filter(|character| !stringprep::tables::commonly_mapped_to_nothing(*character));
    let normalized = normalize_query(mapped);
    if normalized.chars().any(is_prohibited) || violates_bidirectional_rule(&normalized) {
        return Err(());
    }
    Ok(normalized)
}

fn normalize_query(mapped: impl Iterator<Item = char>) -> Zeroizing<String> {
    let mut normalized = Zeroizing::new(String::new());
    let mut assigned = Zeroizing::new(String::new());
    for character in mapped {
        if stringprep::tables::unassigned_code_point(character) {
            normalized.extend(assigned.chars().nfkc());
            assigned.clear();
            normalized.push(character);
        } else {
            assigned.push(character);
        }
    }
    normalized.extend(assigned.chars().nfkc());
    normalized
}

fn is_prohibited(character: char) -> bool {
    stringprep::tables::non_ascii_space_character(character)
        || stringprep::tables::ascii_control_character(character)
        || stringprep::tables::non_ascii_control_character(character)
        || stringprep::tables::private_use(character)
        || stringprep::tables::non_character_code_point(character)
        || stringprep::tables::surrogate_code(character)
        || stringprep::tables::inappropriate_for_plain_text(character)
        || stringprep::tables::inappropriate_for_canonical_representation(character)
        || stringprep::tables::change_display_properties_or_deprecated(character)
        || stringprep::tables::tagging_character(character)
}

fn violates_bidirectional_rule(value: &str) -> bool {
    if !value.chars().any(is_bidi_r_or_al) {
        return false;
    }
    value.chars().any(is_bidi_l)
        || value
            .chars()
            .next()
            .is_none_or(|character| !is_bidi_r_or_al(character))
        || value
            .chars()
            .next_back()
            .is_none_or(|character| !is_bidi_r_or_al(character))
}

fn is_bidi_r_or_al(character: char) -> bool {
    unicode32_bidi::contains(unicode32_bidi::BIDI_R_OR_AL, character)
}

fn is_bidi_l(character: char) -> bool {
    unicode32_bidi::contains(unicode32_bidi::BIDI_L, character)
}
