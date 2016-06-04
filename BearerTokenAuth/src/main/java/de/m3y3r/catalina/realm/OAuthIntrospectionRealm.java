package de.m3y3r.catalina.realm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.realm.RealmBase;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.http.fileupload.IOUtils;

/**
 * RFC7662 (OAuth 2.0 Token Introspection)
 * @author thomas
 *
 */
public class OAuthIntrospectionRealm extends RealmBase {

	private static  Log logger = LogFactory.getLog(OAuthIntrospectionRealm.class);

	//FIXME: ensure that those works in all cases... be safe for now
	private static Pattern pActive = Pattern.compile("\"active\": *(true|false)");
	private static Pattern pScope = Pattern.compile("\"scope\": *\"([ \\x21\\x23-\\x5B\\x5D-\\x7E]*)\"");
	private static Pattern pClientId = Pattern.compile("\"client_id\": *\"([\\w-]*)\"");
	private static Pattern pUsername = Pattern.compile("\"username\": *\"([\\w-]*)\"");

	@Override
	protected String getName() {
		return "OAuthIntroRealm";
	}

	@Override
	protected String getPassword(String username) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected Principal getPrincipal(String token) {
		String introspectToken = introspectToken(token);

		Matcher mActive = pActive.matcher(introspectToken);
		if(!mActive.find() || Boolean.valueOf(mActive.group(1)).equals(Boolean.FALSE)) {
			return null;
		}

		List<String> roles = new ArrayList<>();
		Matcher mScope = pScope.matcher(introspectToken);
		if(mScope.find()) {
			String scopes = mScope.group(1);
			if(!scopes.isEmpty()) {
				for(String scope: scopes.split(" ")) {
					roles.add(scope);
				}
			}
		}

		String username = null;
		String clientId = null;
		Matcher mUsername = pUsername.matcher(introspectToken);
		Matcher mClientId = pClientId.matcher(introspectToken);
		if(mUsername.find()) {
			username = mUsername.group(1);
		}
		if(mClientId.find()) {
			clientId = mClientId.group(1);
		}
		return new GenericPrincipal("" + username + '-' + clientId, null, roles, new Principal() {
			@Override
			public String getName() {
				return introspectToken;
			}
		});
	}

	private String introspectToken(String accessToken) {
		try {
			URL ep = new URL(getEndpointIntrospection());
			URLConnection con = ep.openConnection();
			if(con instanceof HttpURLConnection) {
				HttpURLConnection huc = (HttpURLConnection) con;
				huc.setInstanceFollowRedirects(false);
				huc.setReadTimeout(Integer.parseInt(getHttpReadTimeout()));
				huc.setConnectTimeout(Integer.parseInt(getHttpConnectTimeout()));

				/* section 2.1 Introspection Request
				 * FIXME: can be protected by BASIC auth or BEARER auth
				 * we assume BASIC auth here
				 */
				String userPassword = getClientId() + ':' + getClientSecret();
				String b64 = Base64.encodeBase64String(userPassword.getBytes(StandardCharsets.ISO_8859_1));
				huc.setRequestProperty("Authorization", "Basic " + b64);
				huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
				huc.setDoOutput(true);
				String requestData = "token=" + accessToken;
				huc.getOutputStream().write(requestData.getBytes(StandardCharsets.ISO_8859_1));
				huc.getOutputStream().flush();
				if (huc.getResponseCode() == HttpServletResponse.SC_OK) {
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					IOUtils.copy(huc.getInputStream(), baos);
					String introspectionToken = new String(baos.toByteArray(), StandardCharsets.UTF_8);
					return introspectionToken;
				}
			}
		} catch(IOException e) {
			logger.error("failed to call introspection endpoint", e);
		}
		return null;
	}

	/* endpoint config */
	private String endpointIntrospection;
	private String httpConnectTimeout = "3000";
	private String httpReadTimeout = "3000";

	/* endpoint basic auth */
	private String clientId;
	private String clientSecret;

	public String getEndpointIntrospection() {
		return endpointIntrospection;
	}

	public void setEndpointIntrospection(String endpointIntrospection) {
		this.endpointIntrospection = endpointIntrospection;
	}

	public String getHttpConnectTimeout() {
		return httpConnectTimeout;
	}

	public void setHttpConnectTimeout(String httpConnectTimeout) {
		this.httpConnectTimeout = httpConnectTimeout;
	}

	public String getHttpReadTimeout() {
		return httpReadTimeout;
	}

	public void setHttpReadTimeout(String httpReadTimeout) {
		this.httpReadTimeout = httpReadTimeout;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
}
