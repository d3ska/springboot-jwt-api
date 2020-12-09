package pl.deska.springbootjwtapi.api;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/books")
public class BookApi {

    private final List<String> books;

    public BookApi() {
        this.books = new ArrayList<>();
        books.add("Spring Boot 2");
        books.add("Spring in Action 5");
        books.add("Json Web Token");
    }


    @GetMapping
    public List<String> getBooks(){
        return books;
    }

    @PostMapping
    public void addBook(@RequestBody String book){
        books.add(book);
    }
}
