/*
 *
 * Copyright (C) 2018 Taktik SA
 *
 * This file is part of FreeHealthConnector.
 *
 * FreeHealthConnector is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation.
 *
 * FreeHealthConnector is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with FreeHealthConnector.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package org.taktik.freehealth.middleware.service

import org.taktik.connector.business.domain.common.GenAsyncResponse
import org.taktik.connector.business.medadminurses.domain.MedAdminRequestListType
import org.taktik.freehealth.middleware.domain.hcpadm.MedAdminNurseList
import java.util.UUID

interface MedAdminNurseService {

    fun sendRequestList(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?,
        fedCode:Int,
        requestList: MedAdminRequestListType
                             ): GenAsyncResponse


    fun getMedAdminMessages(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?
    ): MedAdminNurseList?

    fun confirmMedAdminMessages(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String?,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?,
        medAdminMessagesReference: List<String>
    ): Boolean

    fun confirmMedAdminAcks(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String?,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?,
        mdaAcksHashes: List<String>
    ): Boolean
}
