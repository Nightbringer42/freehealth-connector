//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2022.09.16 at 10:40:22 AM CEST 
//


package org.taktik.connector.business.medadminurses.domain;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PalliativeCareGroupType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PalliativeCareGroupType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Responsible" type="{urn:be:cin:mycarenet:1.0:carenet:types}NihiiType"/>
 *         &lt;element name="ThirdPartyPayer" type="{urn:be:cin:mycarenet:1.0:carenet:types}NihiiType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PalliativeCareGroupType", namespace = "urn:be:cin:mycarenet:1.0:carenet:types", propOrder = {
    "responsible",
    "thirdPartyPayer"
})
public class PalliativeCareGroupType {

    @XmlElement(name = "Responsible", namespace = "urn:be:cin:mycarenet:1.0:carenet:types", required = true)
    protected String responsible;
    @XmlElement(name = "ThirdPartyPayer", namespace = "urn:be:cin:mycarenet:1.0:carenet:types")
    protected String thirdPartyPayer;

    /**
     * Gets the value of the responsible property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getResponsible() {
        return responsible;
    }

    /**
     * Sets the value of the responsible property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setResponsible(String value) {
        this.responsible = value;
    }

    /**
     * Gets the value of the thirdPartyPayer property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getThirdPartyPayer() {
        return thirdPartyPayer;
    }

    /**
     * Sets the value of the thirdPartyPayer property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setThirdPartyPayer(String value) {
        this.thirdPartyPayer = value;
    }

}