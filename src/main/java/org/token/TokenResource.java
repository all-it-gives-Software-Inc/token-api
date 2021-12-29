package org.token;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.SneakyThrows;
import org.token.service.TokenService;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

@Path("/token")
public class TokenResource {

    @Inject
    TokenService service;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/converter")
    @SneakyThrows
    public JWTClaimsSet converToken(@HeaderParam("token") String token){
        return service.getPayloadToken(token);
    }
}