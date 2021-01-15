package org.jaaslounge.decoding.kerberos;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.jaaslounge.decoding.DecodingException;

@Deprecated
public final class KerberosUtil {

    private KerberosUtil() {}

    public static <T extends ASN1Primitive> T readAs(ASN1InputStream stream, Class<T> type)
            throws DecodingException {

        ASN1Primitive derObject;
        try {
            derObject = stream.readObject();
        } catch(IOException e) {
            throw new DecodingException("kerberos.token.invalid", null, e);
        }

        return check(derObject, type);
    }

    public static <T extends ASN1Primitive> T readAs(ASN1TaggedObject tagged, Class<T> type)
            throws DecodingException {

        return check(tagged.getObject(), type);
    }

    public static <T extends ASN1Primitive> T check(Object object, Class<T> type)
            throws DecodingException {

        if(!type.isInstance(object)) {
            Object[] args = new Object[]{type, object.getClass()};
            throw new DecodingException("kerberos.object.cast", args, null);
        }

        return type.cast(object);
    }
}
