package de.m3y3r.catalina.authenticator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;

/**
 * RFC6750 - "Authorization Request Header Field" bearer token authenticator
 * @author thomas
 */
public class BearerTokenAuthenticator extends AuthenticatorBase {

	@Override
	protected String getAuthMethod() {
		return "BEARER";
	}

	@Override
	public boolean authenticate(Request request, HttpServletResponse response) throws IOException {
		MessageBytes authorization = request.getCoyoteRequest().getMimeHeaders().getValue("authorization");
		if (authorization != null) {
			ByteChunk authBc = authorization.getByteChunk();
			if (authBc.startsWithIgnoreCase(getAuthMethod(), 0)) {
				int to = authBc.getOffset() + getAuthMethod().length() + 1;
				int ti = authBc.getLength() + getAuthMethod().length() - 1;

				String token = new String(authBc.getBuffer(), to, ti, StandardCharsets.ISO_8859_1);
				Principal principal = context.getRealm().authenticate(token);
				if(principal != null) {
					register(request, response, principal, getAuthMethod(), token, null);
					return true;
				}
			}
		}

		// the request could not be authenticated, so reissue the challenge
		StringBuilder value = new StringBuilder(16);
		value.append("Bearer realm=\"");
		value.append(getRealmName(context));
		value.append('\"');
		response.setHeader(AUTH_HEADER_NAME, value.toString());
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	}
}
