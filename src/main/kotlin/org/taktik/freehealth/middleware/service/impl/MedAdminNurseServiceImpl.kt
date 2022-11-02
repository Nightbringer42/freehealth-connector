package org.taktik.freehealth.middleware.service.impl

import be.cin.encrypted.BusinessContent
import be.cin.encrypted.EncryptedKnownContent
import be.cin.mycarenet.esb.common.v2.*
import be.cin.nip.async.generic.*
import be.cin.types.v1.FaultType
import be.fgov.ehealth.etee.crypto.utils.KeyManager
import be.fgov.ehealth.technicalconnector.signature.AdvancedElectronicSignatureEnumeration
import be.fgov.ehealth.technicalconnector.signature.SignatureBuilderFactory
import be.fgov.ehealth.technicalconnector.signature.transformers.EncapsulationTransformer
import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl
import ma.glasnost.orika.MapperFacade
import org.apache.commons.codec.binary.Base64
import org.joda.time.DateTime
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import org.taktik.connector.business.domain.common.GenAsyncResponse
import org.taktik.connector.business.genericasync.builders.BuilderFactory
import org.taktik.connector.business.genericasync.service.impl.GenAsyncServiceImpl
import org.taktik.connector.business.medadminurses.domain.MedAdminRequestListType
import org.taktik.connector.business.mycarenetcommons.mapper.SendRequestMapper
import org.taktik.connector.business.mycarenetdomaincommons.builders.BlobBuilderFactory
import org.taktik.connector.business.mycarenetdomaincommons.domain.McnPackageInfo
import org.taktik.connector.business.mycarenetdomaincommons.mapper.DomainBlobMapper
import org.taktik.connector.business.mycarenetdomaincommons.util.McnConfigUtil
import org.taktik.connector.technical.config.ConfigFactory
import org.taktik.connector.technical.handler.domain.WsAddressingHeader
import org.taktik.connector.technical.idgenerator.IdGeneratorFactory
import org.taktik.connector.technical.service.etee.Crypto
import org.taktik.connector.technical.service.etee.CryptoFactory
import org.taktik.connector.technical.service.keydepot.KeyDepotService
import org.taktik.connector.technical.service.keydepot.impl.KeyDepotManagerImpl
import org.taktik.connector.technical.service.sts.security.Credential
import org.taktik.connector.technical.service.sts.security.impl.KeyStoreCredential
import org.taktik.connector.technical.utils.ConnectorIOUtils
import org.taktik.connector.technical.utils.ConnectorXmlUtils
import org.taktik.connector.technical.utils.IdentifierType
import org.taktik.connector.technical.utils.MarshallerHelper
import org.taktik.freehealth.middleware.dao.User
import org.taktik.freehealth.middleware.domain.hcpadm.MedAdminNurseAck
import org.taktik.freehealth.middleware.domain.hcpadm.MedAdminNurseList
import org.taktik.freehealth.middleware.domain.hcpadm.MedAdminNurseMessage
import org.taktik.freehealth.middleware.domain.memberdata.*
import org.taktik.freehealth.middleware.dto.mycarenet.CommonOutput
import org.taktik.freehealth.middleware.dto.mycarenet.MycarenetConversation
import org.taktik.freehealth.middleware.exception.MissingTokenException
import org.taktik.freehealth.middleware.service.MedAdminNurseService
import org.taktik.freehealth.middleware.service.STSService
import org.taktik.icure.cin.saml.extensions.ResponseList
import org.w3c.dom.Document
import org.w3c.dom.NodeList
import java.io.StringWriter
import java.net.URI
import java.net.URISyntaxException
import java.util.*
import javax.xml.bind.JAXBContext
import javax.xml.transform.TransformerException
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMResult
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import javax.xml.ws.soap.SOAPFaultException

@Service
class MedAdminNurseServiceImpl(val stsService: STSService, val keyDepotService: KeyDepotService, val mapper: MapperFacade) :
    MedAdminNurseService {
    @Value("\${mycarenet.timezone}")
    internal val mcnTimezone: String = "Europe/Brussels"
    private val genAsyncService = GenAsyncServiceImpl("hcpadm")

    private val log = LoggerFactory.getLogger(this.javaClass)
    private val config = ConfigFactory.getConfigValidator(listOf())
    private val keyDepotManager = KeyDepotManagerImpl.getInstance(keyDepotService)

    override fun sendRequestList(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?,
        fedCode:Int,
        requestList: MedAdminRequestListType
    ): GenAsyncResponse {

        requireNotNull(keystoreId) { "Keystore id cannot be null" }
        requireNotNull(tokenId) { "Token id cannot be null" }

        val samlToken = stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
            ?: throw IllegalArgumentException("Cannot obtain token for MedAdminNurse operations")
        val keystore = stsService.getKeyStore(keystoreId, passPhrase)!!
        val credential = KeyStoreCredential(keystoreId, keystore, "authentication", passPhrase, samlToken.quality)
        //XADES fail if encryptRequest
        val encryptRequest = true

        val inputReference =
            IdGeneratorFactory.getIdGenerator().generateId()//.let { if (istest) "T" + it.substring(1) else it }
        val now = DateTime().withMillisOfSecond(0)

        val hokPrivateKeys = KeyManager.getDecryptionKeys(keystore, passPhrase.toCharArray())
        val crypto = CryptoFactory.getCrypto(credential, hokPrivateKeys)
        val principal = SecurityContextHolder.getContext().authentication?.principal as? User
        val packageInfo = McnConfigUtil.retrievePackageInfo(
            "hcpadm",
            principal?.mcnLicense,
            principal?.mcnPassword,
            principal?.mcnPackageName
        )

        val postHeader = WsAddressingHeader(URI("urn:be:cin:nip:async:generic:post:msg")).apply {
            faultTo = "http://www.w3.org/2005/08/addressing/anonymous"
            replyTo = "http://www.w3.org/2005/08/addressing/anonymous"
            messageID = URI("uuid:" + UUID.randomUUID())
        }

        val issueInstantDateTime = DateTime()
        val issueInstant = XMLGregorianCalendarImpl(issueInstantDateTime.toGregorianCalendar())




        val unEncryptedMessage = ConnectorXmlUtils.toByteArray(requestList)

        val blobBuilder = BlobBuilderFactory.getBlobBuilder("hcpadm")
        val detailId = "_" + IdGeneratorFactory.getIdGenerator("uuid").generateId();

//        val blob = unEncryptedMessage.let { aqb ->
//            if (encryptRequest) {
//                val identifierTypeString = config.getProperty("hcpadm.keydepot.identifiertype", "CBE")
//                val identifierValue = config.getLongProperty("hcpadm.keydepot.identifiervalue", 820563481L)
//                val applicationId = config.getProperty("hcpadm.keydepot.application", "MYCARENET")
//                val identifierSource = 48
//                val identifier = IdentifierType.lookup(identifierTypeString, null as String?, identifierSource)
//
//                val mbEtk = if (identifier == null) {
//                    throw IllegalStateException("invalid configuration : identifier with type ]$identifierTypeString[ for source ETKDEPOT not found")
//                } else {
//                    keyDepotManager.getEtkSet(IdentifierType.CBE, identifierValue, applicationId, keystoreId, false)
//                }
//
//                crypto.seal(
//                    Crypto.SigningPolicySelector.WITH_NON_REPUDIATION, mbEtk, ConnectorXmlUtils.toByteArray(
//                        EncryptedKnownContent().apply {
//                            replyToEtk = keyDepotManager.getETK(credential, keystoreId).encoded
//                            businessContent = BusinessContent().apply {
//                                id = detailId
//                                value = aqb
//                            }
//                        })
//                ).let {
//                    blobBuilder.build(it, "none", detailId, "text/xml", "M4A_XML", "encryptedForKnownBED")
//                }
//            } else blobBuilder.build(aqb, "none", detailId, "text/xml", "M4A_XML")
//        }

        //TEST From eAttest
        val encryptedKnownContent = EncryptedKnownContent()
        encryptedKnownContent.replyToEtk = keyDepotManager.getETK(credential, keystoreId).encoded
        val businessContent = BusinessContent().apply { id = detailId }
        encryptedKnownContent.businessContent = businessContent

        businessContent.value = unEncryptedMessage
        log.info("Request is: " + businessContent.value.toString(Charsets.UTF_8))
        val xmlByteArray = handleEncryption(encryptedKnownContent, credential, crypto, detailId)

        val blob =
            BlobBuilderFactory.getBlobBuilder("attest")
                .build(
                    xmlByteArray,
                    "none",
                    detailId,
                    "text/xml",
                    null as String?,
                    "encryptedForKnownBED"
                )
        blob.messageName = "M4A_XML"
        //END TEST From eAttest

        val ci = CommonInput().apply {
            request = be.cin.mycarenet.esb.common.v2.RequestType().apply {
                isIsTest = true
            }
            origin = buildOriginType(packageInfo, hcpQuality, hcpNihii, hcpSsin)

            this.inputReference = inputReference
        }

//        val unsealedData =
//            crypto.unseal(Crypto.SigningPolicySelector.WITHOUT_NON_REPUDIATION, blob.content).contentAsByte
//        val encryptedKnownContentBis =
//            MarshallerHelper(EncryptedKnownContent::class.java, EncryptedKnownContent::class.java).toObject(
//                unsealedData
//            )
//        val xades = encryptedKnownContentBis!!.xades
//        val signatureVerificationResult = xades?.let {
//            val builder = SignatureBuilderFactory.getSignatureBuilder(AdvancedElectronicSignatureEnumeration.XAdES)
//            val options = emptyMap<String, Any>()
//            builder.verify(unsealedData, it, options)
//        } ?: SignatureVerificationResult().apply {
//            errors.add(SignatureVerificationError.SIGNATURE_NOT_PRESENT)
//        }

        //Xades T fail => Access denied to timestamp authority
//        val xades = BlobUtil.generateXades(credential, BlobMapper.mapBlobTypefromBlob(blob), "hcpadm").value

//        val post = BuilderFactory.getRequestObjectBuilder("hcpadm").buildPostRequest(ci, SendRequestMapper.mapBlobToCinBlob(blob), xades)
        val post = BuilderFactory.getRequestObjectBuilder("hcpadm").buildPostRequest(ci, SendRequestMapper.mapBlobToCinBlob(blob), null)

        val header: WsAddressingHeader
        try {
            header = WsAddressingHeader(URI("urn:be:cin:nip:async:generic:post:msg"))
            header.to = URI("urn:nip:destination:io:$fedCode") //FIXME: Check where to send => pass FED code to controller
            header.faultTo = "http://www.w3.org/2005/08/addressing/anonymous"
            header.replyTo = "http://www.w3.org/2005/08/addressing/anonymous"
            header.messageID = URI("" + UUID.randomUUID())
        } catch (e: URISyntaxException) {
            throw IllegalStateException(e)
        }
//with or without Xades, dies here
        val postResponse = genAsyncService.postRequest(samlToken, post, header)

        val tack = postResponse.getReturn()
        val success = tack.resultMajor != null && tack.resultMajor == "urn:nip:tack:result:major:success"

//        if (!success) {
//            throw IllegalStateException("postRequest failed : " + tack.resultMinor)
//        }

        return GenAsyncResponse().apply {
            result = postResponse.`return`.resultMajor == "urn:nip:tack:result:major:success"
            this.tack = postResponse.`return`
            mycarenetConversation = MycarenetConversation().apply {
                this.transactionRequest =
                    MarshallerHelper(Post::class.java, Post::class.java).toXMLByteArray(post).toString(Charsets.UTF_8)
                this.transactionResponse =
                    MarshallerHelper(PostResponse::class.java, PostResponse::class.java).toXMLByteArray(postResponse)
                        .toString(Charsets.UTF_8)
                postResponse?.soapResponse?.writeTo(this.soapResponseOutputStream())
                postResponse?.soapRequest?.writeTo(this.soapRequestOutputStream())
            }
        };
    }

    private fun buildOriginType(
        packageInfo: McnPackageInfo,
        hcpQuality: String,
        hcpNihii: String,
        hcpSsin: String?
    ) = OrigineType().apply {
            `package` = PackageType().apply {
                license = LicenseType().apply {
                    username = packageInfo.userName
                    password = packageInfo.password
                }
                name = ValueRefString().apply { value = packageInfo.packageName }
            }
            careProvider = CareProviderType().apply {
                nihii =
                    NihiiType().apply {
                        quality = hcpQuality;
                        value = ValueRefString()
                            .apply { value = hcpNihii.padEnd(11, '0') }
                    }

                physicalPerson = IdType().apply {
                    nihii = NihiiType().apply {
                        quality = hcpQuality;
                        value = ValueRefString()
                            .apply { value = hcpNihii.padEnd(11, '0') }
                    }

                    hcpSsin?.let {
                        ssin = ValueRefString().apply {
                            value = hcpSsin;
                        }
                    }
                }

                organization = IdType().apply {
                    nihii =
                        NihiiType().apply {
                            quality = hcpQuality;
                            value = ValueRefString()
                                .apply { value = hcpNihii.padEnd(11, '0') }
                        }
                }
            }
        }

    //Pompé d'eAttest
    private fun handleEncryption(
        request: EncryptedKnownContent,
        credential: Credential,
        crypto: Crypto,
        detailId: String
    ): ByteArray? {
        val marshaller = JAXBContext.newInstance(request.javaClass).createMarshaller()
        val res = DOMResult()
        marshaller.marshal(request, res)

        val doc = res.node as Document

        val nodes = doc.getElementsByTagNameNS("urn:be:cin:encrypted", "EncryptedKnownContent")
        val content = toStringOmittingXmlDeclaration(nodes)
        val builder = SignatureBuilderFactory.getSignatureBuilder(AdvancedElectronicSignatureEnumeration.XAdES)
        val options = HashMap<String, Any>()
        val tranforms = ArrayList<String>()
        tranforms.add("http://www.w3.org/2000/09/xmldsig#base64")
        tranforms.add("http://www.w3.org/2001/10/xml-exc-c14n#")
        options.put("transformerList", tranforms)
        options.put("baseURI", detailId)
        options.put("encapsulate", true)
        options.put("encapsulate-transformer", EncapsulationTransformer { signature ->
            val result = signature.ownerDocument.createElementNS("urn:be:cin:encrypted", "Xades")
            result.textContent = Base64.encodeBase64String(ConnectorXmlUtils.toByteArray(signature))
            result
        })
        val encryptedKnowContent = builder.sign(credential, content.toByteArray(charset("UTF-8")), options)
        return crypto.seal(
            Crypto.SigningPolicySelector.WITH_NON_REPUDIATION,
            KeyDepotManagerImpl.getInstance(keyDepotService).getEtkSet(
                IdentifierType.CBE,
                820563481L,
                "MYCARENET",
                null,
                false
            ),
            encryptedKnowContent
        )
    }

    @Throws(TransformerException::class)
    private fun toStringOmittingXmlDeclaration(nodes: NodeList): String {
        val sb = StringBuilder()
        val tf = TransformerFactory.newInstance()
        val serializer = tf.newTransformer()
        serializer.setOutputProperty("omit-xml-declaration", "yes")

        for (i in 0 until nodes.length) {
            val sw = StringWriter()
            serializer.transform(DOMSource(nodes.item(i)), StreamResult(sw))
            sb.append(sw.toString())
        }

        return sb.toString()
    }

    override fun getMedAdminMessages(
        keystoreId: UUID,
        tokenId: UUID,
        passPhrase: String,
        hcpQuality: String,
        hcpNihii: String,
        hcpName: String,
        hcpSsin: String?,
        fedCode: Int,
        messageNames: List<String>?
    ): MedAdminNurseList? {

        val samlToken = stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
            ?: throw MissingTokenException("Cannot obtain token for MedAdminNurse operations")
        val keystore = stsService.getKeyStore(keystoreId, passPhrase)!!
        val credential = KeyStoreCredential(keystoreId, keystore, "authentication", passPhrase, samlToken.quality)
        val hokPrivateKeys = KeyManager.getDecryptionKeys(keystore, passPhrase.toCharArray())
        val crypto = CryptoFactory.getCrypto(credential, hokPrivateKeys)

        val principal = SecurityContextHolder.getContext().authentication?.principal as? User
        val packageInfo = McnConfigUtil.retrievePackageInfo(
            "hcpadm",
            principal?.mcnLicense,
            principal?.mcnPassword,
            principal?.mcnPackageName
        )

        val getHeader = WsAddressingHeader(URI("urn:be:cin:nip:async:generic:get:query")).apply {
            messageID = URI(IdGeneratorFactory.getIdGenerator("uuid").generateId())
//            to = URI("urn:nip:destination:io:$fedCode")
        }

        val get = Get().apply {
            msgQuery = MsgQuery().apply {
                isInclude = true
                max = 100
                this.messageNames.add("")
//                this.messageNames.add("M4A_CNF_XML")
//                this.messageNames.add("M4A_XML")
            }
            tAckQuery = Query().apply {
                isInclude = true
                max = 100
            }
            origin = buildOriginType(packageInfo, hcpQuality, hcpNihii, hcpSsin)
        }

        val response = genAsyncService.getRequest(samlToken, get, getHeader)
//        log.info("Response : " + response);

        val b64 = java.util.Base64.getEncoder()
        val listOfMedAdminDecryptedResponseContent : ArrayList<String> = arrayListOf()
        var List<FaultType>? genericErrors = null;
        return try {
            MedAdminNurseList(
                medAdminNurseMessageList = response.`return`.msgResponses?.map {
                    var data: ByteArray? = if (it.detail.contentEncoding == "deflate") ConnectorIOUtils.decompress(
                        DomainBlobMapper.mapToBlob(it.detail).content) else DomainBlobMapper.mapToBlob(it.detail).content

                    if (it.detail.messageName == "REJECT") {
                        val reject = if (it.detail.contentEncryption == "encryptedForKnownRecipient") {
                            val unsealedData =
                                crypto.unseal(Crypto.SigningPolicySelector.WITHOUT_NON_REPUDIATION, data).contentAsByte
                            val encryptedKnownContent = MarshallerHelper(
                                EncryptedKnownContent::class.java,
                                EncryptedKnownContent::class.java
                            ).toObject(unsealedData)
                            MarshallerHelper(RejectInb::class.java, RejectInb::class.java).toObject(
                                if (encryptedKnownContent.businessContent.contentEncoding == "deflate")
                                    ConnectorIOUtils.decompress(encryptedKnownContent.businessContent.value) else encryptedKnownContent.businessContent.value
                            )
                        } else {
                            MarshallerHelper(RejectInb::class.java, RejectInb::class.java).toObject(data)
                        }
                        listOfMedAdminDecryptedResponseContent.add(ConnectorXmlUtils.toString(reject))
                    }

                    val responseList = if (it.detail.contentEncryption == "encryptedForKnownRecipient") {
                            val unsealedData = crypto.unseal(Crypto.SigningPolicySelector.WITHOUT_NON_REPUDIATION, data).contentAsByte
                            val encryptedKnownContent = MarshallerHelper(EncryptedKnownContent::class.java, EncryptedKnownContent::class.java).toObject(unsealedData)
                            MarshallerHelper(ResponseList::class.java, ResponseList::class.java).toObject(
                                if (encryptedKnownContent.businessContent.contentEncoding == "deflate")
                                    ConnectorIOUtils.decompress(encryptedKnownContent.businessContent.value) else encryptedKnownContent.businessContent.value
                            )
                        } else {
                            MarshallerHelper(ResponseList::class.java, ResponseList::class.java).toObject(data)
                        }


                    listOfMedAdminDecryptedResponseContent.add(ConnectorXmlUtils.toString(responseList))

                    MedAdminNurseMessage(
                        commonOutput = CommonOutput(
                            inputReference = it.commonOutput.inputReference,
                            outputReference = it.commonOutput.outputReference,
                            nipReference = it.commonOutput.nipReference
                        ),
                        errors = null,
                        genericErrors = null,
                        reference = it.detail.reference,
                        appliesTo = null,
                        complete = null,
                        io = null,
//                        medAdminNurseResponse = responseList.responses.map {
//                            MemberDataBatchResponse(
//                                assertions = it.anies.map{
//                                    MarshallerHelper(Assertion::class.java, Assertion::class.java).toObject(it)
//                                },
//                                status = MdaStatus(
//                                    it.status.statusCode?.value,
//                                    it.status.statusCode?.statusCode?.value
//                                ),
//                                errors = it.status?.statusDetail?.anies?.map {
//                                    FaultType().apply {
//                                        faultCode = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "FaultCode").item(0)?.textContent
//                                        faultSource = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "FaultSource").item(0)?.textContent
//                                        message = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Message").item(0)?.let {
//                                            StringLangType().apply {
//                                                value = it.textContent
//                                                lang = it.attributes.getNamedItem("lang")?.textContent
//                                            }
//                                        }
//
//                                        it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Detail").let {
//                                            if (it.length > 0) {
//                                                details = DetailsType()
//                                            }
//                                            for (i in 0 until it.length) {
//                                                details.details.add(DetailType().apply {
//                                                    it.item(i).let {
//                                                        detailCode = (it as Element).getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "DetailCode").item(0)?.textContent
//                                                        detailSource = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "DetailSource").item(0)?.textContent
//                                                        location = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Location").item(0)?.textContent
//                                                        message = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Message").item(0)?.let {
//                                                            StringLangType().apply {
//                                                                value = it.textContent
//                                                                lang = it.attributes.getNamedItem("lang")?.textContent
//                                                            }
//                                                        }
//                                                    }
//                                                })
//                                            }
//                                        }
//                                    }
//                                },
//                                issueInstant = it.issueInstant,
//                                inResponseTo = it.inResponseTo,
//                                issuer = it.issuer.value,
//                                responseId = it.id
//                            )
//                                .apply {
//                                    this.errors?.forEach {
//                                        it.details?.details?.forEach { d ->
//                                            this.myCarenetErrors += extractError(this.status?.code1, this.status?.code2, d.location, d.detailCode).toList()
//                                        }
//                                    }
//                                }
//                        },
                        valueHash = it.detail?.hashValue?.let { b64.encodeToString(it)}
                    )

                },
                acks = response.`return`.tAckResponses?.map {
                    MedAdminNurseAck(
                        major = it.tAck.resultMajor,
                        minor = it.tAck.resultMinor,
                        message = it.tAck.resultMessage,
                        date = null
                    )
                },
                mycarenetConversation = MycarenetConversation().apply {
                    this.transactionRequest = org.taktik.connector.technical.utils.MarshallerHelper(be.cin.nip.async.generic.Get::class.java, be.cin.nip.async.generic.Get::class.java).toXMLByteArray(get).toString(kotlin.text.Charsets.UTF_8)
                    this.transactionResponse = org.taktik.connector.technical.utils.MarshallerHelper(be.cin.nip.async.generic.GetResponse::class.java, be.cin.nip.async.generic.GetResponse::class.java).toXMLByteArray(response).toString(kotlin.text.Charsets.UTF_8)
                    response?.soapResponse?.writeTo(this.soapResponseOutputStream())
                    soapRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(Charsets.UTF_8)
                    this.decryptedResponseContent = listOfMedAdminDecryptedResponseContent
                },
                date = null,
                genericErrors = null
            )
        }catch (e: SOAPFaultException){
            return MedAdminNurseList(
                mycarenetConversation = MycarenetConversation().apply {
                    this.transactionRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(Charsets.UTF_8)
                    this.transactionResponse = MarshallerHelper(GetResponse::class.java, GetResponse::class.java).toXMLByteArray(response).toString(Charsets.UTF_8)
                    response?.soapResponse?.writeTo(this.soapResponseOutputStream())
                    soapRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(Charsets.UTF_8)
                    this.decryptedResponseContent = listOfMedAdminDecryptedResponseContent
                },
                acks = null,
                date = null,
                medAdminNurseMessageList =  null,
                genericErrors = listOf(FaultType().apply {
                    faultSource = e.message
                    faultCode = e.fault?.faultCode
                })
            )
        }


//        return try {
//            MemberDataList(
//                memberDataMessageList = response.`return`.msgResponses?.map {
//                    var data: ByteArray? = if (it.detail.contentEncoding == "deflate") ConnectorIOUtils.decompress(
//                        DomainBlobMapper.mapToBlob(it.detail).content) else DomainBlobMapper.mapToBlob(it.detail).content
//                    val responseList = if (it.detail.contentEncryption == "encryptedForKnownRecipient") {
//                        val unsealedData = crypto.unseal(Crypto.SigningPolicySelector.WITHOUT_NON_REPUDIATION, data).contentAsByte
//                        val encryptedKnownContent = MarshallerHelper(EncryptedKnownContent::class.java, EncryptedKnownContent::class.java).toObject(unsealedData)
//                        MarshallerHelper(ResponseList::class.java, ResponseList::class.java).toObject(
//                            if (encryptedKnownContent.businessContent.contentEncoding == "deflate")
//                                ConnectorIOUtils.decompress(encryptedKnownContent.businessContent.value) else encryptedKnownContent.businessContent.value
//                        )
//                    } else {
//                        MarshallerHelper(ResponseList::class.java, ResponseList::class.java).toObject(data)
//                    }
//
//                    listOfMdaDecryptedResponseContent.add(ConnectorXmlUtils.toString(responseList))
//
//                    MemberDataMessage(
//                        commonOutput = CommonOutput(
//                            inputReference = it.commonOutput.inputReference,
//                            outputReference = it.commonOutput.outputReference,
//                            nipReference = it.commonOutput.nipReference
//                        ),
//                        errors = null,
//                        genericErrors = null,
//                        reference = it.detail.reference,
//                        appliesTo = null,
//                        complete = null,
//                        io = null,
//                        memberDataResponse = responseList.responses.map {
//                            MemberDataBatchResponse(
//                                assertions = it.anies.map{
//                                    MarshallerHelper(Assertion::class.java, Assertion::class.java).toObject(it)
//                                },
//                                status = MdaStatus(
//                                    it.status.statusCode?.value,
//                                    it.status.statusCode?.statusCode?.value
//                                ),
//                                errors = it.status?.statusDetail?.anies?.map {
//                                    FaultType().apply {
//                                        faultCode = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "FaultCode").item(0)?.textContent
//                                        faultSource = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "FaultSource").item(0)?.textContent
//                                        message = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Message").item(0)?.let {
//                                            StringLangType().apply {
//                                                value = it.textContent
//                                                lang = it.attributes.getNamedItem("lang")?.textContent
//                                            }
//                                        }
//
//                                        it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Detail").let {
//                                            if (it.length > 0) {
//                                                details = DetailsType()
//                                            }
//                                            for (i in 0 until it.length) {
//                                                details.details.add(DetailType().apply {
//                                                    it.item(i).let {
//                                                        detailCode = (it as Element).getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "DetailCode").item(0)?.textContent
//                                                        detailSource = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "DetailSource").item(0)?.textContent
//                                                        location = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Location").item(0)?.textContent
//                                                        message = it.getElementsByTagNameWithOrWithoutNs("urn:be:cin:types:v1", "Message").item(0)?.let {
//                                                            StringLangType().apply {
//                                                                value = it.textContent
//                                                                lang = it.attributes.getNamedItem("lang")?.textContent
//                                                            }
//                                                        }
//                                                    }
//                                                })
//                                            }
//                                        }
//                                    }
//                                },
//                                issueInstant = it.issueInstant,
//                                inResponseTo = it.inResponseTo,
//                                issuer = it.issuer.value,
//                                responseId = it.id
//                            )
//                                .apply {
//                                    this.errors?.forEach {
//                                        it.details?.details?.forEach { d ->
//                                            this.myCarenetErrors += extractError(this.status?.code1, this.status?.code2, d.location, d.detailCode).toList()
//                                        }
//                                    }
//                                }
//                        },
//                        valueHash = it.detail?.hashValue?.let { b64.encodeToString(it)}
//                    )
//
//                },
//                acks = response.`return`.tAckResponses?.map {
//                    MemberDataAck(
//                        major = it.tAck.resultMajor,
//                        minor = it.tAck.resultMinor,
//                        message = it.tAck.resultMessage,
//                        date = null
//                    )
//                },
//                mycarenetConversation = MycarenetConversation().apply {
//                    this.transactionRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(
//                        Charsets.UTF_8)
//                    this.transactionResponse = MarshallerHelper(GetResponse::class.java, GetResponse::class.java).toXMLByteArray(response).toString(
//                        Charsets.UTF_8)
//                    response?.soapResponse?.writeTo(this.soapResponseOutputStream())
//                    soapRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(Charsets.UTF_8)
//                    this.decryptedResponseContent = listOfMdaDecryptedResponseContent
//                },
//                date = null,
//                genericErrors = null
//            )
//        }catch (e:SOAPFaultException){
//            return MemberDataList(
//                mycarenetConversation = MycarenetConversation().apply {
//                    this.transactionRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(
//                        Charsets.UTF_8)
//                    this.transactionResponse = MarshallerHelper(GetResponse::class.java, GetResponse::class.java).toXMLByteArray(response).toString(
//                        Charsets.UTF_8)
//                    response?.soapResponse?.writeTo(this.soapResponseOutputStream())
//                    soapRequest = MarshallerHelper(Get::class.java, Get::class.java).toXMLByteArray(get).toString(Charsets.UTF_8)
//                    this.decryptedResponseContent = listOfMdaDecryptedResponseContent
//                },
//                acks = null,
//                date = null,
//                memberDataMessageList =  null,
//                genericErrors = listOf(FaultType().apply {
//                    faultSource = e.message
//                    faultCode = e.fault?.faultCode
//                })
//            )
//        }

    }

//    override fun confirmMemberDataMessages(
//        keystoreId: UUID,
//        tokenId: UUID,
//        passPhrase: String,
//        hcpQuality: String?,
//        hcpNihii: String,
//        hcpName: String,
//        hcpSsin: String?,
//        mdaMessagesReference: List<String>): Boolean {
//        if (mdaMessagesReference.isEmpty()) {
//            return true
//        }
//
//        val samlToken =
//            stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
//                ?: throw MissingTokenException("Cannot obtain token for MDA operations")
//
//        val confirmheader = WsAddressingUtil.createHeader("", "urn:be:cin:nip:async:generic:confirm:hash")
//
//        val confirm = Confirm()
//        confirm.origin = buildOriginType(hcpNihii, hcpName, hcpQuality, hcpSsin)
//        confirm.msgRefValues.addAll(mdaMessagesReference)
//
//        genAsyncService.confirmRequest(samlToken, confirm, confirmheader)
//
//        return true
//    }
//
//    override fun confirmMemberDataAcks(
//        keystoreId: UUID,
//        tokenId: UUID,
//        passPhrase: String,
//        hcpQuality: String?,
//        hcpNihii: String,
//        hcpName: String,
//        hcpSsin: String?,
//        mdaAcksHashes: List<String>
//    ): Boolean {
//        if (mdaAcksHashes.isEmpty()) {
//            return true
//        }
//        val samlToken =
//            stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
//                ?: throw MissingTokenException("Cannot obtain token for MDA operations")
//
//        val confirmheader = WsAddressingUtil.createHeader("", "urn:be:cin:nip:async:generic:confirm:hash")
//        val confirm =
//            BuilderFactory.getRequestObjectBuilder("mda")
//                .buildConfirmRequestWithHashes(buildOriginType(hcpNihii, hcpName, hcpQuality, hcpSsin),
//                    listOf(),
//                    mdaAcksHashes.map { valueHash -> java.util.Base64.getDecoder().decode(valueHash) })
//
//        genAsyncService.confirmRequest(samlToken, confirm, confirmheader)
//
//        return true
//    }


//
//    override fun loadMessages(
//        keystoreId: UUID,
//        tokenId: UUID,
//        passPhrase: String,
//        hcpNihii: String,
//        hcpSsin: String,
//        hcpFirstName: String,
//        hcpLastName: String,
//        language: String,
//        limit: Int
//    ): List<EfactMessage> {
//        val samlToken =
//            stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
//                ?: throw MissingTokenException("Cannot obtain token for Efact operations")
//
//        val principal = SecurityContextHolder.getContext().authentication?.principal as? User
//
//        requireNotNull(keystoreId) { "Keystore id cannot be null" }
//        requireNotNull(tokenId) { "Token id cannot be null" }
//
//        val inputReference = "" + System.currentTimeMillis()
//        val requestObjectBuilder = try {
//            BuilderFactory.getRequestObjectBuilder("invoicing")
//        } catch (e: Exception) {
//            throw IllegalArgumentException(e)
//        }
//
//        val ci = CommonInput().apply {
//            request = be.cin.mycarenet.esb.common.v2.RequestType().apply {
//                isIsTest = isTest
//            }
//            origin = buildOriginType(McnConfigUtil.retrievePackageInfo(
//                "hcpadm",
//                principal?.mcnLicense,
//                principal?.mcnPassword,
//                principal?.mcnPackageName
//            ),samlToken.quality, hcpNihii, hcpSsin)
//            this.inputReference = inputReference
//        }
//
//        val header = try {
//            WsAddressingHeader(URI("urn:be:cin:nip:async:generic:get:query")).apply {
//                faultTo = "http://www.w3.org/2005/08/addressing/anonymous"
//                replyTo = "http://www.w3.org/2005/08/addressing/anonymous"
//                messageID = URI("" + UUID.randomUUID())
//            }
//        } catch (e: URISyntaxException) {
//            throw IllegalStateException(e)
//        }
//
//        var batchSize = Math.min(64, limit)
//        var retries = 8
//
//        val eFactMessages = ArrayList<EfactMessage>()
//
//        while (retries-- > 0) {
//            val msgQuery = requestObjectBuilder.createMsgQuery(batchSize, true, "M4A_CNF_XML", "M4A_FLAT", "M4A_XML")
//            val query = requestObjectBuilder.createQuery(batchSize, true)
//
//            val getResponse: GetResponse
//            try {
//                getResponse =
//                    genAsyncService.getRequest(
//                        samlToken,
//                        requestObjectBuilder.buildGetRequest(ci.origin, msgQuery, query),
//                        header
//                    )
//            } catch (e: TechnicalConnectorException) {
//                if ((e.message?.contains("SocketTimeout") == true) && batchSize > 1) {
//                    batchSize /= 4
//                    continue
//                }
//                throw IllegalStateException(e)
//            } catch (e: SOAPFaultException) {
//                if (e.message?.contains("Not enough time") == true) {
//                    Thread.sleep(30000)
//                    continue
//                }
//                throw IllegalStateException(e)
//            }
//
//            eFactMessages += getResponse.getReturn().msgResponses.map { r ->
//                EfactMessage().apply {
//                    id = r.detail.id
//                    name = r.detail.messageName
//
//                    commonOutput = CommonOutput().apply {
//                        this.inputReference = r.commonOutput.inputReference
//                        this.nipReference = r.commonOutput.nipReference
//                        this.outputReference = r.commonOutput.outputReference
//                    }
//                    try {
//                        detail =
//                            String(
//                                ConnectorIOUtils.decompress(IOUtils.toByteArray(r.detail.value.inputStream)),
//                                Charsets.UTF_8
//                            ) //This starts with 92...
//
//                        message =
//                            BelgianInsuranceInvoicingFormatReader(language).parse(StringReader(this.detail!!))?.map {
//                                Record(
//                                    mapper.map(it.description, RecordOrSegmentDescription::class.java),
//                                    it.zones.map { z ->
//                                        Zone(
//                                            mapper.map(z.zoneDescription, ZoneDescription::class.java),
//                                            z.value
//                                        )
//                                    },
//                                    mapper.map(it.errorDetail, ErrorDetail::class.java)
//                                )
//                            }
//                        xades = Base64.encodeBase64String(r.xadesT.value)
//                        hashValue = Base64.encodeBase64String(r.detail.hashValue)
//                    } catch (e: IOException) {
//                    }
//                }
//            } + getResponse.getReturn().tAckResponses.map { r ->
//                EfactMessage().apply {
//                    id = r.tAck.appliesTo.replace("urn:nip:reference:input:".toRegex(), "")
//                    name = "tAck"
//                    try {
//                        tAck = r.tAck
//                        xades = Base64.encodeBase64String(r.xadesT.value)
//                        hashValue = Base64.encodeBase64String(r.tAck.value)
//                    } catch (e: IOException) {
//                    }
//                }
//            }
//
//            break
//        }
//        return eFactMessages
//    }
//
//    override fun confirmAcks(
//        keystoreId: UUID,
//        tokenId: UUID,
//        passPhrase: String,
//        hcpNihii: String,
//        hcpSsin: String,
//        hcpFirstName: String,
//        hcpLastName: String,
//        valueHashes: List<String>
//    ): Boolean {
//        if (valueHashes.isEmpty()) {
//            return true
//        }
//        val samlToken =
//            stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
//                ?: throw MissingTokenException("Cannot obtain token for Efact operations")
//
//        val confirmheader = WsAddressingUtil.createHeader("", "urn:be:cin:nip:async:generic:confirm:hash")
//
//        val confirm =
//            BuilderFactory.getRequestObjectBuilder("invoicing")
//                .buildConfirmRequestWithHashes(buildOriginType(
//                    samlToken.quality,
//                    hcpNihii,
//                    hcpSsin,
//                    hcpFirstName,
//                    hcpLastName
//                ),
//                    listOf(),
//                    valueHashes.map { valueHash -> java.util.Base64.getDecoder().decode(valueHash) })
//
//        genAsyncService.confirmRequest(samlToken, confirm, confirmheader)
//
//        return true
//    }
//
//    override fun confirmMessages(
//        keystoreId: UUID,
//        tokenId: UUID,
//        passPhrase: String,
//        hcpNihii: String,
//        hcpSsin: String,
//        hcpFirstName: String,
//        hcpLastName: String,
//        valueHashes: List<String>
//    ): Boolean {
//        if (valueHashes.isEmpty()) {
//            return true
//        }
//        val samlToken =
//            stsService.getSAMLToken(tokenId, keystoreId, passPhrase)
//                ?: throw MissingTokenException("Cannot obtain token for Efact operations")
//
//        val confirmheader = WsAddressingUtil.createHeader("", "urn:be:cin:nip:async:generic:confirm:hash")
//        val confirm =
//            BuilderFactory.getRequestObjectBuilder("invoicing")
//                .buildConfirmRequestWithHashes(
//                    buildOriginType(samlToken.quality, hcpNihii, hcpSsin, hcpFirstName, hcpLastName),
//                    valueHashes.map { valueHash -> java.util.Base64.getDecoder().decode(valueHash) },
//                    listOf()
//                )
//
//        genAsyncService.confirmRequest(samlToken, confirm, confirmheader)
//
//        return true
//    }

}
