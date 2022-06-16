package com.fx.dev;

import com.nimbusds.jose.jwk.ECKey;

import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws JOSEException, ParseException {
        ECKey signJWK = new ECKeyGenerator(Curve.P_256).keyID("123")
                .generate();
        
        ECKey encJWK =  new ECKeyGenerator(Curve.P_256).keyID("456")
        .generate();
        
        System.out.println(signJWK.toJSONString());



        System.out.println("signed Pubkey: " + signJWK.toPublicJWK().toJSONString());

        System.out.println(encJWK.toJSONString());

        
        System.out.println("enc Pubkey: " + encJWK.toPublicJWK().toJSONString());

        // build claim

       JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
       .subject("s=S8829314B,u=1c0cee38-3a8f-4f8a-83bc-7a0e4c59d6a9").
       issuer("https://stg-id.singpass.gov.sg")
       .audience("xxNsTfleQMHoW6tbUgSVNwnLWQ0xTeV0")
       .expirationTime(new Date())
       .issueTime(new Date())
       .claim("amr", "[ \"pwd\", \"swk\" ]")
       .claim("nonce", "alh5DS2Gfndv9i0jXYViqGIhiQdP4+4BrUvBhDXBYKk=")
       .build();
       
       System.out.println(claimsSet);

       // build ID jwt

       SignedJWT signedJWT =  new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signJWK.getKeyID()).build(),claimsSet);

       JWSSigner signer =  new ECDSASigner(signJWK);


       System.out.println("----------");

    //    System.out.println(signedJWT.serialize());

       signedJWT.sign(signer);

       System.out.println(signedJWT.serialize());



        //create JWE

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).contentType("JWT").build(),new Payload(signedJWT));

        jweObject.encrypt(new ECDHEncrypter(encJWK.toPublicJWK()));

        System.out.println("encrypted jwe");

        String jweOutPut = jweObject.serialize();
        System.out.println(jweOutPut);


        JWEObject jweObject2  = JWEObject.parse(jweOutPut);

        jweObject2.decrypt(new ECDHDecrypter(encJWK)); 

        SignedJWT signedJWT2 = jweObject2.getPayload().toSignedJWT();

        
        System.out.println("verify sign result:" + signedJWT2.verify(new ECDSAVerifier(signJWK)));


        System.out.println(signedJWT2.getJWTClaimsSet().getSubject());
        

    }
}
