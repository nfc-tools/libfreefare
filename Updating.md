# Updating from 0.4.0 to ?

* The abstract `MifareTag` structure was renamed to `FreefareTag` in order to avoid confusion when adding support for non-MIFARE tags;
  Users of libfreefare can simply replace any occurence of `MifareTag` with `FreefareTag`.
* The `mifare_tag_type` enum was renamed to `freefare_tag_type` (this should not have incidence for users) and defined values for MIFARE tags (that is *all* values) have been prefixed with `MIFARE_` for consistency.
  Users of libfreefare will need to adjust comparisons of the return value of `freefare_get_tag_type()` if they use this in their code.

