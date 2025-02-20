package pd.security.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class MessagesController {

    @GetMapping("/user-messages")
    public List<String> getMessages() {
        return List.of("Message 1", "Message 2", "Message 3");
    }
}
