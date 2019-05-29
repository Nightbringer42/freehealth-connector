//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.1 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.05.29 at 05:57:25 PM CEST 
//


package extensions;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the extensions package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _AssertionType_QNAME = new QName("urn:be:cin:nippin:memberdata:saml:extension", "AssertionType");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: extensions
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link Facet }
     * 
     */
    public Facet createFacet() {
        return new Facet();
    }

    /**
     * Create an instance of {@link AttributeQueryList }
     * 
     */
    public AttributeQueryList createAttributeQueryList() {
        return new AttributeQueryList();
    }

    /**
     * Create an instance of {@link ResponseList }
     * 
     */
    public ResponseList createResponseList() {
        return new ResponseList();
    }

    /**
     * Create an instance of {@link Facet.Dimension }
     * 
     */
    public Facet.Dimension createFacetDimension() {
        return new Facet.Dimension();
    }

    /**
     * Create an instance of {@link ExtensionsType }
     * 
     */
    public ExtensionsType createExtensionsType() {
        return new ExtensionsType();
    }

    /**
     * Create an instance of {@link AdviceBaseType }
     * 
     */
    public AdviceBaseType createAdviceBaseType() {
        return new AdviceBaseType();
    }

    /**
     * Create an instance of {@link AdviceType }
     * 
     */
    public AdviceType createAdviceType() {
        return new AdviceType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}
     * 
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link String }{@code >}
     */
    @XmlElementDecl(namespace = "urn:be:cin:nippin:memberdata:saml:extension", name = "AssertionType")
    public JAXBElement<String> createAssertionType(String value) {
        return new JAXBElement<String>(_AssertionType_QNAME, String.class, null, value);
    }

}
