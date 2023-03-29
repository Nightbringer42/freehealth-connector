package be.cin.mycarenet._1_0.carenet.types;

import org.joda.time.DateTime;
import org.taktik.connector.technical.adapter.XmlDateNoTzAdapter;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.Serializable;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(
   name = "PalliativeCareDetailType",
   propOrder = {"nurseReference", "requester", "periodStart", "group", "usualDoctor", "careProvider"}
)
@XmlRootElement(
   name = "PalliativeCareDetail"
)
public class PalliativeCareDetail implements Serializable {
   private static final long serialVersionUID = 1L;
   @XmlElement(
      name = "NurseReference",
      required = true
   )
   protected String nurseReference;
   @XmlElement(
      name = "Requester",
      required = true
   )
   protected String requester;
   
   @XmlElement(name = "PeriodStart", namespace = "urn:be:cin:mycarenet:1.0:carenet:types", required = true)
   @XmlSchemaType(name = "date")
   protected XMLGregorianCalendar periodStart;
   @XmlElement(
      name = "Group",
      required = true
   )
   protected PalliativeCareGroupType group;
   @XmlElement(
      name = "UsualDoctor",
      required = true
   )
   protected String usualDoctor;
   @XmlElement(
      name = "CareProvider",
      required = true
   )
   protected PalliativeCareCareProviderType careProvider;

   public String getNurseReference() {
      return this.nurseReference;
   }

   public void setNurseReference(String value) {
      this.nurseReference = value;
   }

   public String getRequester() {
      return this.requester;
   }

   public void setRequester(String value) {
      this.requester = value;
   }

   public XMLGregorianCalendar getPeriodStart() {
      return this.periodStart;
   }

   public void setPeriodStart(XMLGregorianCalendar value) {
      this.periodStart = value;
   }

   public PalliativeCareGroupType getGroup() {
      return this.group;
   }

   public void setGroup(PalliativeCareGroupType value) {
      this.group = value;
   }

   public String getUsualDoctor() {
      return this.usualDoctor;
   }

   public void setUsualDoctor(String value) {
      this.usualDoctor = value;
   }

   public PalliativeCareCareProviderType getCareProvider() {
      return this.careProvider;
   }

   public void setCareProvider(PalliativeCareCareProviderType value) {
      this.careProvider = value;
   }
}
