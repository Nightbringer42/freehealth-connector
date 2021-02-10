//
//  Generated from FHIR Version 4.0.1-9346c8cc45
//
package org.taktik.icure.fhir.entities.r4.consent

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import kotlin.Boolean
import kotlin.String
import kotlin.collections.List
import org.taktik.icure.fhir.entities.r4.backboneelement.BackboneElement
import org.taktik.icure.fhir.entities.r4.extension.Extension
import org.taktik.icure.fhir.entities.r4.reference.Reference

/**
 * Consent Verified by patient or family
 *
 * Whether a treatment instruction (e.g. artificial respiration yes or no) was verified with the
 * patient, his/her family or another authorized person.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
class ConsentVerification(
  override var extension: List<Extension> = listOf(),
  /**
   * Unique id for inter-element referencing
   */
  override var id: String? = null,
  override var modifierExtension: List<Extension> = listOf(),
  /**
   * When consent verified
   */
  var verificationDate: String? = null,
  /**
   * Has been verified
   */
  var verified: Boolean? = null,
  /**
   * Person who verified
   */
  var verifiedWith: Reference? = null
) : BackboneElement
