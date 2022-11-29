package ma.eolba.transfer.dtos;

import lombok.*;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class  UserDetailsDto implements Serializable {

	private static final long serialVersionUID = 1L;
	private String fullName;
	List<String> authorities;
	private String id;
	private String username;
	private String password;
	private String firstName;
	private String lastName;
	private String role;
	private String email;
	private String phoneNumber;
	private String statut;

	public UserDetailsDto(String username, String role, String email) {
		this.username = username;
		this.role = role;
		this.email = email;
	}
}
