package com.configuration.Service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	//holds the secretkey we are creating initially
	private SecretKey key;
	
	//will map the details that are needed for the claims
	private Map<String, Object> claimsMap = new HashMap<String, Object>();
	
	//here we are generating the secretkey during the object creation
	public JwtService() {
        try {
        	//KeyGenerator class will get its instance and use hmac SHA algo to generate key
			KeyGenerator keyGen = KeyGenerator.getInstance("hmacSHA256");
			//generate the secretkey
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	

	//returns the secret key
	private SecretKey getKey() {
		return key;
	}
	
	//will generate the jwt token
	public String generateToken(String username) {
		// TODO Auto-generated method stub
		/*
		 * Jwts - class for JSON Web Token
		 * builder() method initializes a new builder instance for creating a JWT
		 * claims() This method allows you to set custom claims in the JWT.  - pass map as arguments
		 * subject() his method sets the subject claim of the JWT.- pass the username as argument
		 * issuedAt() method helps us to provide the token issue date
		 * expiration() method helps us to provide the token expiration date - pass milliseconds as argument
		 * signWith() method helps us to mention which key has to use to sign - pass secret key as argument
		 * compact() This method finalizes the building process and generates the JWT as a compact, URL-safe string.
		 * */
		return Jwts.builder()
                .claims(claimsMap)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000)) 
                // Set expiration to 1 hour in milli secounds
                .signWith(key)
                .compact();
	}
	
	//username extraction part
	public String extractUsername(String jwtToken) {
		/*
		 * Here we are passing the arguments of jwtToken and Claims class method getSubject
		 * The Claims::getSubject method is used to access the subject claim from a JWT.
		 * */
		return extractClaim(jwtToken,Claims::getSubject);
	}

	
	//extracts the claim and it will take a function
	/*
	 * return type is <T> T which represents Generic type
	 * there are some set of generic types which we can use in java.
	 * Common Generic Placeholders:
			T stands for Type.
			E stands for Element (used in collections like List<E>, Set<E>).
			K stands for Key (used in Map<K, V>).
			V stands for Value (used in Map<K, V>).
			N stands for Number.
			Why Use Generics?
	Type Safety: Generics allow the compiler to check that the types used are correct, reducing the chances of ClassCastException at runtime.
	Code Reusability: You can write more flexible and reusable code since you can apply it to different types without needing to rewrite it for each type.
	 * */
	private <T> T extractClaim(String jwtToken, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(jwtToken);
		return claimResolver.apply(claims);
	}

	private Claims extractAllClaims(String jwtToken) {
		/*
		 * Jwts.parser() - The parser is used to decode and validate JWTs.
		 * verifyWith() - This method is used to specify the key that will be used to verify the signature of the JWT.
		 * build() -  This finalizes the setup of the parser.
		 * parseSignedClaim() - This method takes the JWT as a string (jwtToken) and attempts to parse it.
		 * getPayload() - This method extracts the payload (the claims) from the parsed JWT
		 * */
		return Jwts.parser()
				.verifyWith(getKey())
				.build()
				.parseSignedClaims(jwtToken)
				.getPayload();
	}


	//token validation
	public boolean validateToken(String jwtToken, UserDetails userDetails) {
		//calling the extractUsername method to get the username from token
		final String userName = extractUsername(jwtToken);
		//validating the username by checking in the database and expiration of the token 
		Boolean validated = userName.equals(userDetails.getUsername()) && !isTokenExipred(jwtToken);
		return validated;
	}
	
	//checking if token is expired or not by before date
	private boolean isTokenExipred(String jwtToken) {
		/*
		 * It returns true if the expiration date of the token is before the current date and time, indicating that the token is no longer valid.
		   It returns false if the token has not yet expired.
		 */
		return extractExpirationToken(jwtToken).before(new Date());
	}

	//extracting the expiration token
	private Date extractExpirationToken(String jwtToken) {
		//extracting the expiration using the extractClaim method
		return extractClaim(jwtToken,Claims::getExpiration);
	}

}
