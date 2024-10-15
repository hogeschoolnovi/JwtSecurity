package nl.novi.les17JWT.services;

import jakarta.transaction.Transactional;
import nl.novi.les17JWT.entities.Role;
import nl.novi.les17JWT.entities.User;
import nl.novi.les17JWT.mappers.RoleMapper;
import nl.novi.les17JWT.mappers.UserMapper;
import nl.novi.les17JWT.models.UserModel;
import nl.novi.les17JWT.repositories.RoleRepository;
import nl.novi.les17JWT.repositories.UserRepository;
import nl.novi.les17JWT.security.ApiUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
public class ApiUserDetailService implements UserDetailsService {

    private final UserMapper userMapper;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final RoleMapper roleMapper;

    public ApiUserDetailService(UserRepository userRepository, RoleRepository roleRepository, UserMapper userMapper, RoleMapper roleMapper) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
    }

    @Transactional
    public boolean createUser(UserModel userModel, List<String> roles) {
        var validRoles = roleRepository.findByRoleNameIn(roles);

        var user = userMapper.toEntity(userModel);
        for (Role role: validRoles ) {
            user.getRoles().add(role);
        }
        updateRolesWithUser(user);
        var savedUser = userRepository.save(user);
        userModel.setId(savedUser.getId());
        return savedUser != null;
    }

    private void updateRolesWithUser(User user) {
        for (Role role: user.getRoles()) {
            role.getUsers().add(user);
        }
    }
    @Transactional
    public boolean createUser(UserModel userModel, String[] roles) {
        return createUser(userModel, Arrays.asList(roles));
    }

    public Optional<UserModel> getUserByUserName(String username) {
        var user = userRepository.findByUserName(username);
        return getOptionalUserModel(user);
    }


    public Optional<UserModel> getUserByUserNameAndPassword(String username, String password) {
        var user = userRepository.findByUserNameAndPassword(username, password);
        return getOptionalUserModel(user);
    }

    private Optional<UserModel> getOptionalUserModel(Optional<User> user) {
        if (user.isPresent()) {
            return Optional.of(userMapper.fromEntity(user.get()));
        }
        return Optional.empty();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserModel> user = getUserByUserName(username);
        if (user.isEmpty()) { throw new UsernameNotFoundException(username);}
        return new ApiUserDetails(user.get());
    }

    public boolean updatePassword(UserModel userModel) {
        Optional<User> user = userRepository.findById(userModel.getId());
        if (user.isEmpty()) { throw new UsernameNotFoundException(userModel.getId().toString());}
        // convert to entity to get the encode password
        var update_user = userMapper.toEntity(userModel);
        var entity = user.get();
        entity.setPassword(update_user.getPassword());
        return userRepository.save(entity) != null;
    }
}