package nandraina.AuthSpring_Angular.repository;

import nandraina.AuthSpring_Angular.model.UserEntity;
import org.springframework.data.repository.CrudRepository;

public interface AuthRepository extends CrudRepository<UserEntity, Long> {
     UserEntity findByUsername(String username);
}
