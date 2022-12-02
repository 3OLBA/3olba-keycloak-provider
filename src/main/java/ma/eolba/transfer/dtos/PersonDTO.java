package ma.eolba.transfer.dtos;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import ma.eolba.transfer.enums.RoleType;

import java.util.Date;

@Builder
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class PersonDTO {

    private String name;
    private String lastName;
    private String username;
    private String cin;
    private String email;
    private String role;
    private String password;
    private String phoneNumber;
    private Boolean isDeleted;
    private Boolean isDisabled;
    private String birthDay;
    private Date createdDate;
    private Date modifiedDate;

    public PersonDTO(String email, String username, String password, String role) {
        this.email = email;
        this.username = username;
        this.password = password;
        this.role = role;
    }

    @Override
    public String toString() {
        return "PersonDTO{" +
                "username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", role='" + role + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
