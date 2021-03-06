package pdfboxEsign.esign.pdfsigner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

/**
 * @author Akhilesh Kumar
 * @version 1.0
 * @date 01/06/2021 23:11
 */
public class TSAClient {
	private static final Log LOG = LogFactory.getLog(TSAClient.class);

	private static final DigestAlgorithmIdentifierFinder ALGORITHM_OID_FINDER =
			new DefaultDigestAlgorithmIdentifierFinder();

	private final URL url;
	private final String username;
	private final String password;
	private final MessageDigest digest;

	// SecureRandom.getInstanceStrong() would be better, but sometimes blocks on Linux
	private static final Random RANDOM = new SecureRandom();

	/**
	 * @param url      the URL of the TSA service
	 * @param username user name of TSA
	 * @param password password of TSA
	 * @param digest   the message digest to use
	 */
	public TSAClient(URL url, String username, String password, MessageDigest digest) {
		this.url = url;
		this.username = username;
		this.password = password;
		this.digest = digest;
	}

	/**
	 * @param content
	 * @return the time stamp token
	 * @throws IOException if there was an error with the connection or data from the TSA server,
	 *                     or if the time stamp response could not be validated
	 */
	public TimeStampToken getTimeStampToken(InputStream content) throws IOException {
		digest.reset();
		DigestInputStream dis = new DigestInputStream(content, digest);
		while (dis.read() != -1) {
			// do nothing
		}
		byte[] hash = digest.digest();

		// 32-bit cryptographic nonce
		int nonce = RANDOM.nextInt();

		// generate TSA request
		TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
		tsaGenerator.setCertReq(true);
		ASN1ObjectIdentifier oid = ALGORITHM_OID_FINDER.find(digest.getAlgorithm()).getAlgorithm();
		TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));

		// get TSA response
		byte[] tsaResponse = getTSAResponse(request.getEncoded());

		TimeStampResponse response;
		try {
			response = new TimeStampResponse(tsaResponse);
			response.validate(request);
		} catch (TSPException e) {
			throw new IOException(e);
		}

		TimeStampToken timeStampToken = response.getTimeStampToken();
		if (timeStampToken == null) {
			// https://www.ietf.org/rfc/rfc3161.html#section-2.4.2
			throw new IOException("Response from " + url +
					" does not have a time stamp token, status: " + response.getStatus() +
					" (" + response.getStatusString() + ")");
		}

		return timeStampToken;
	}

	// gets response data for the given encoded TimeStampRequest data
	// throws IOException if a connection to the TSA cannot be established
	private byte[] getTSAResponse(byte[] request) throws IOException {
		LOG.debug("Opening connection to TSA server");

		// todo: support proxy servers
		URLConnection connection = url.openConnection();
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setRequestProperty("Content-Type", "application/timestamp-query");

		LOG.debug("Established connection to TSA server");

		if (username != null && password != null && !username.isEmpty() && !password.isEmpty()) {
			connection.setRequestProperty(username, password);
		}

		// read response
		try (OutputStream output = connection.getOutputStream()) {
			output.write(request);
		} catch (IOException ex) {
			LOG.error("Exception when writing to " + this.url, ex);
			throw ex;
		}

		LOG.debug("Waiting for response from TSA server");

		byte[] response;
		try (InputStream input = connection.getInputStream()) {
			response = IOUtils.toByteArray(input);
		} catch (IOException ex) {
			LOG.error("Exception when reading from " + this.url, ex);
			throw ex;
		}

		LOG.debug("Received response from TSA server");

		return response;
	}
}
