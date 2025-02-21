package pd.security.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ContactsController {

    @GetMapping("/contacts")
    public List<String> getMessages() {
        return List.of("Sir Chats-a-Lot", "Spammy McCaller", "Voicemail King");
    }
}
