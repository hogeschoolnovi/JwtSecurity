package nl.novi.les17JWT.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import nl.novi.les17JWT.dtos.UserChangePassWordRequestDTO;
import nl.novi.les17JWT.dtos.UserDTOMapper;
import nl.novi.les17JWT.dtos.UserRequestDTO;
import nl.novi.les17JWT.helpers.UrlHelper;
import nl.novi.les17JWT.services.ApiUserDetailService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final UserDTOMapper userDTOMapper;
    private final ApiUserDetailService apiUserDetailService;
    private final HttpServletRequest request;

    public UserController(UserDTOMapper userDTOMapper, ApiUserDetailService apiUserDetailService, HttpServletRequest request) {
        this.userDTOMapper = userDTOMapper;
        this.apiUserDetailService = apiUserDetailService;
        this.request = request;
    }

    @PostMapping("/users")
    public ResponseEntity<?> CreateUser(@RequestBody @Valid UserRequestDTO userDTO)
    {
        var userModel = userDTOMapper.mapToModel(userDTO);
        userModel.setEnabled(true);
        if(!apiUserDetailService.createUser(userModel, userDTO.getRoles())) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.created(UrlHelper.getCurrentUrlWithId(request, userModel.getId())).build();
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<?> ChangePassword(@PathVariable Long id, @RequestBody @Valid UserChangePassWordRequestDTO userDTO)
    {
        var userModel = userDTOMapper.mapToModel(userDTO, id);
        if(!apiUserDetailService.updatePassword(userModel)) {
            return ResponseEntity.badRequest().build();
        }
        return  ResponseEntity.ok().build();
    }
}
