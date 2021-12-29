package org.token.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder(toBuilder = true)
public class UserResponse{
    public String sub;
    public String iss;
    public Integer exp;
    public Integer userId;
    public Integer iat;
    public List<String> authorities;
    public String email;
}

