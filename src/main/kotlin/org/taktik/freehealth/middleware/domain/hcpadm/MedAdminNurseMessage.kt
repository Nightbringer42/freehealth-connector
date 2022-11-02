package org.taktik.freehealth.middleware.domain.hcpadm

import be.cin.types.v1.FaultType
import org.taktik.connector.business.medadminurses.domain.MedAdminResponseListType
import org.taktik.freehealth.middleware.dto.mycarenet.CommonOutput
import org.taktik.freehealth.middleware.dto.mycarenet.MycarenetError

class MedAdminNurseMessage(
    var commonOutput: CommonOutput? = null,
    var complete: Boolean? = false,
    var errors: List<MycarenetError>? = null,
    var genericErrors: List<FaultType>? = null,
    var medAdminNurseResponse: MedAdminResponseListType? = null,
    var io: String? = null,
    var appliesTo: String? = null,
    var reference: String? = null,
    var valueHash: String? = null
)
