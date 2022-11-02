package org.taktik.freehealth.middleware.domain.hcpadm

import be.cin.types.v1.FaultType
import org.taktik.freehealth.middleware.dto.mycarenet.MycarenetConversation
import java.util.*

class MedAdminNurseList(
    val mycarenetConversation: MycarenetConversation?,
    val acks: List<MedAdminNurseAck>?,
    val medAdminNurseMessageList: List<MedAdminNurseMessage>?,
    val date: Date?,
    val genericErrors: List<FaultType>?
)
