package com.auth0.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.SessionUtils;
import com.auth0.client.auth.AuthAPI;
import com.auth0.json.auth.UserInfo;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.net.Request;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.input.ReaderInputStream;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Filter class to check if a valid session exists. This will be true if the User Id is present.
 */
@WebFilter(urlPatterns = "/portal/*")
public class Auth0Filter implements Filter {
	private JWTVerifier verifier;
    private String domain;
    private String clientId;
    private String clientSecret;

    @Inject
    private com.auth0.example.UserInfo info;

   private static String readAll(Reader rd) throws IOException {
      StringBuilder sb = new StringBuilder();
      int cp;
      while ((cp = rd.read()) != -1) {
         sb.append((char) cp);
      }
      return sb.toString();
   }

   public static JSONObject readJsonFromUrl(String url) throws IOException, JSONException {
      InputStream is = new URL(url).openStream();
      try {
         BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
         String jsonText = readAll(rd);
         JSONObject json = new JSONObject(jsonText);
         return json;
      } finally {
         is.close();
      }
   }

    private RSAPublicKey getPublicKey(String pem) throws IOException, GeneralSecurityException {
       byte[] encoded = Base64.decodeBase64(pem);
       KeyFactory kf = KeyFactory.getInstance("RSA");
       RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
       return pubKey;
    }

    private RSAPublicKey getPublicKeyFromCertificate(String certificate) throws GeneralSecurityException, IOException {
       CertificateFactory fact = CertificateFactory.getInstance("X.509");
       X509Certificate cer = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(certificate.getBytes("UTF-8")));
       return (RSAPublicKey) cer.getPublicKey();
    }

    public void init(FilterConfig filterConfig) throws ServletException {
      try {
         final String pem = readJsonFromUrl("https://lumeer.eu.auth0.com/.well-known/jwks.json").getJSONArray("keys").getJSONObject(0).getJSONArray("x5c").getString(0);
         final StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
         int i = 0;
         while (i < pem.length()) {
            sb.append(pem, i, Math.min(i + 64, pem.length()));
            sb.append("\n");
            i += 64;
         }
         sb.append("-----END CERTIFICATE-----");
         final String pemN = sb.toString();
         System.out.println("Náš PEM: " + pemN);
         final RSAPublicKey pubKey = getPublicKeyFromCertificate(pemN);
         final Verification verification = JWT.require(Algorithm.RSA256(pubKey, null));
         verifier = verification.acceptExpiresAt(60).build();
      } catch (Exception e) {
         e.printStackTrace();
      }
    	// One minute tolerance window for verification
        domain = filterConfig.getServletContext().getInitParameter("com.auth0.domain");
        clientId = filterConfig.getServletContext().getInitParameter("com.auth0.clientId");
        clientSecret = filterConfig.getServletContext().getInitParameter("com.auth0.clientSecret");
    }

    /**
     * Perform filter check on this request - verify the User Id is present.
     *
     * @param request  the received request
     * @param response the response to send
     * @param next     the next filter chain
     **/
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain next) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String bearer = req.getHeader("Authorization");
        if (bearer != null) {
           bearer = bearer.substring(bearer.indexOf("Bearer") + 7).trim();
           SessionUtils.set(req, "accessToken", bearer);
        }

        String accessToken = (String) SessionUtils.get(req, "accessToken");
        String idToken = (String) SessionUtils.get(req, "idToken");
        System.out.println("Access token " + accessToken);
        System.out.println("Id token " + idToken);
        if (idToken != null) {
        	final DecodedJWT jwt = JWT.decode(idToken);


        	// Need to properly configure certificates to use verifier
        	// verifier.verify(idToken);
         if (verifier != null) {
            System.out.println("Verifikujeme!!!");
            verifier.verify(jwt.getToken());
         }
        	if (Instant.now().isAfter(jwt.getExpiresAt().toInstant())) {
                res.sendRedirect(req.getContextPath() + "/login");
                return;
        	}
        }
				System.out.println(this.info);

        if (accessToken != null && verifier != null) {
           System.out.println("Verifikujeme accessToken");
           final DecodedJWT atjwt = JWT.decode(accessToken);
           verifier.verify(atjwt.getToken());
        }

        if (accessToken != null && this.info != null && this.info.getEmail() == null) {
        	final AuthAPI auth0 = new AuthAPI(domain, clientId, clientSecret);
        	final Request<UserInfo> info = auth0.userInfo(accessToken);
        	final String nickname = (String)info.execute().getValues().get("nickname");
        	final String sub = (String)info.execute().getValues().get("sub");
        	final String name = (String)info.execute().getValues().get("name");
        	this.info.setEmail(sub.startsWith("google-oauth2") ? nickname + "@gmail.com" : name);
        }
        if (accessToken == null && idToken == null) {
            res.sendRedirect(req.getContextPath() + "/login");
            return;
        }
        next.doFilter(request, response);
    }

    public void destroy() {
    }
}
