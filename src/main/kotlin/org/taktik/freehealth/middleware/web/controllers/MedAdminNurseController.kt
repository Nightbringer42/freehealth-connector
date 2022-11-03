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

package org.taktik.freehealth.middleware.web.controllers

import ma.glasnost.orika.MapperFacade
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.*
import org.taktik.connector.business.domain.common.GenAsyncResponse
import org.taktik.connector.business.medadminurses.domain.*
import org.taktik.freehealth.middleware.domain.hcpadm.MedAdminNurseList
import org.taktik.freehealth.middleware.service.MedAdminNurseService
import java.util.*

@RestController
@RequestMapping("/hcpadm")
class MedAdminNurseController(val medAdminNurseService: MedAdminNurseService, val mapper: MapperFacade) {


    @PostMapping("/async/request", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    fun sendMedAdminRequestAsync(
        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
        @RequestParam hcpNihii: String,
        @RequestParam hcpName: String,
        @RequestParam fedCode: Int,
        @RequestParam(required = false) hcpQuality: String?,
        @RequestParam(required = false) hcpSsin: String?,
        @RequestBody requestList: MedAdminRequestListType
                             ): GenAsyncResponse {

        return medAdminNurseService.sendRequestList(
            keystoreId = keystoreId,
            passPhrase = passPhrase,
            tokenId = tokenId,
            hcpQuality = hcpQuality ?: "nurse",
            hcpNihii = hcpNihii,
            hcpName = hcpName,
            hcpSsin = hcpSsin,
            fedCode = fedCode,
            requestList = mapper.map(requestList, MedAdminRequestListType::class.java)
        )
    }

    @PostMapping("/async/request/palliative", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    fun sendMedAdminPalliativeRequestAsync(
        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
        @RequestParam hcpNihii: String,
        @RequestParam hcpName: String,
        @RequestParam fedCode: Int,
        @RequestParam(required = false) hcpQuality: String?,
        @RequestParam(required = false) hcpSsin: String?,
        @RequestBody request: SinglePalliativeCareRequestType
    ): GenAsyncResponse {

        val requestList = MedAdminRequestListType()
        requestList.singleNurseContractualCareRequestOrSinglePalliativeCareRequestOrSingleSpecificTechnicalCareRequest.add(mapper.map(request, SinglePalliativeCareRequestType::class.java))

        return medAdminNurseService.sendRequestList(
            keystoreId = keystoreId,
            passPhrase = passPhrase,
            tokenId = tokenId,
            hcpQuality = hcpQuality ?: "nurse",
            hcpNihii = hcpNihii,
            hcpName = hcpName,
            hcpSsin = hcpSsin,
            fedCode = fedCode,
            requestList = requestList)

    }

    @PostMapping("/async/request/contractual-care", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    fun sendMedAdminContractualCareRequestAsync(
        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
        @RequestParam hcpNihii: String,
        @RequestParam hcpName: String,
        @RequestParam fedCode: Int,
        @RequestParam(required = false) hcpQuality: String?,
        @RequestParam(required = false) hcpSsin: String?,
        @RequestBody request: SingleNurseContractualCareRequestType
    ): GenAsyncResponse {

        val requestList = MedAdminRequestListType()
        requestList.singleNurseContractualCareRequestOrSinglePalliativeCareRequestOrSingleSpecificTechnicalCareRequest.add(mapper.map(request, SingleNurseContractualCareRequestType::class.java))

        return medAdminNurseService.sendRequestList(
            keystoreId = keystoreId,
            passPhrase = passPhrase,
            tokenId = tokenId,
            hcpQuality = hcpQuality ?: "nurse",
            hcpNihii = hcpNihii,
            hcpName = hcpName,
            hcpSsin = hcpSsin,
            fedCode = fedCode,
            requestList = requestList)


    }

    @PostMapping("/async/request/technical-care", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    fun sendMedAdminSpecificTechnicalCareRequestAsync(
        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
        @RequestParam hcpNihii: String,
        @RequestParam hcpName: String,
        @RequestParam fedCode: Int,
        @RequestParam(required = false) hcpQuality: String?,
        @RequestParam(required = false) hcpSsin: String?,
        @RequestBody request: SingleSpecificTechnicalCareRequestType
    ): GenAsyncResponse {

        val requestList = MedAdminRequestListType()
        requestList.singleNurseContractualCareRequestOrSinglePalliativeCareRequestOrSingleSpecificTechnicalCareRequest.add(mapper.map(request, SingleSpecificTechnicalCareRequestType::class.java))

        return medAdminNurseService.sendRequestList(
            keystoreId = keystoreId,
            passPhrase = passPhrase,
            tokenId = tokenId,
            hcpQuality = hcpQuality ?: "nurse",
            hcpNihii = hcpNihii,
            hcpName = hcpName,
            hcpSsin = hcpSsin,
            fedCode = fedCode,
            requestList = requestList)

    }

    @PostMapping("/async/messages", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    fun getMedAdminMessageAsync(
        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
        @RequestParam hcpNihii: String,
        @RequestParam hcpName: String,
        @RequestParam(required = false) hcpQuality: String?,
        @RequestParam(required = false) hcpSsin: String?,
        @RequestParam messageNames: List<String>?) : MedAdminNurseList? {

            val medAdminNurseList =  medAdminNurseService.getMedAdminMessages(
                keystoreId = keystoreId,
                tokenId = tokenId,
                passPhrase = passPhrase,
                hcpQuality = hcpQuality ?: "nurse",
                hcpNihii = hcpNihii,
                hcpSsin = hcpSsin,
                hcpName = hcpName,
                messageNames = messageNames)
            return medAdminNurseList
        }

//    @PostMapping("/async/confirm/messages", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
//    fun confirmMemberDataMessagesAsync(
//        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
//        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
//        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
//        @RequestParam hcpNihii: String,
//        @RequestParam hcpName: String,
//        @RequestParam(required = false) hcpQuality: String?,
//        @RequestParam(required = false) hcpSsin: String?,
//        @RequestBody mdaMessagesReference: List<String>) : Boolean?{
//        return medAdminNurseService.confirmMemberDataMessages(
//            keystoreId = keystoreId,
//            tokenId = tokenId,
//            passPhrase = passPhrase,
//            hcpQuality = hcpQuality,
//            hcpNihii = hcpNihii,
//            hcpName = hcpName,
//            hcpSsin = hcpSsin,
//            mdaMessagesReference = mdaMessagesReference
//        )
//        }
//
//
//    @PostMapping("/async/confirm/acks", produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
//    fun confirmMemberDataAcksAsync(
//        @RequestHeader(name = "X-FHC-tokenId") tokenId: UUID,
//        @RequestHeader(name = "X-FHC-keystoreId") keystoreId: UUID,
//        @RequestHeader(name = "X-FHC-passPhrase") passPhrase: String,
//        @RequestParam hcpNihii: String,
//        @RequestParam hcpName: String,
//        @RequestParam(required = false) hcpQuality: String?,
//        @RequestParam(required = false) hcpSsin: String?,
//        @RequestBody mdaAcksHashes: List<String>): Boolean?{
//        return medAdminNurseService.confirmMemberDataAcks(
//            keystoreId = keystoreId,
//            tokenId = tokenId,
//            passPhrase = passPhrase,
//            hcpQuality = hcpQuality,
//            hcpNihii = hcpNihii,
//            hcpName = hcpName,
//            hcpSsin = hcpSsin,
//            mdaAcksHashes = mdaAcksHashes
//        )
//    }

}
