package pdfboxEsign.esign.pdfsigner;

import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSTypedData;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author Akhilesh Kumar
 * @version 1.0
 * @date 01/06/2021 23:08
 */
public class CMSProcessableInputStream implements CMSTypedData {
	private final InputStream in;
	private final ASN1ObjectIdentifier contentType;

	CMSProcessableInputStream(InputStream is) {
		this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
	}

	CMSProcessableInputStream(ASN1ObjectIdentifier type, InputStream is) {
		contentType = type;
		in = is;
	}

	@Override
	public Object getContent() {
		return in;
	}

	@Override
	public void write(OutputStream out) throws IOException {
		// read the content only one time
		IOUtils.copy(in, out);
		in.close();
	}

	@Override
	public ASN1ObjectIdentifier getContentType() {
		return contentType;
	}
}
