
### Step 1: Add Bootstrap to the Project

Add the Bootstrap CSS link to the main HTML layout template.

**index.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Tabs Example</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Tabs Example</h1>
        <ul class="nav nav-tabs" id="myTab" role="tablist">
            <li class="nav-item">
                <a class="nav-link" id="tab1-tab" href="/tab/1" role="tab">Tab 1</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="tab2-tab" href="/tab/2" role="tab">Tab 2</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="tab3-tab" href="/tab/3" role="tab">Tab 3</a>
            </li>
        </ul>
        <div th:replace="fragments/layout :: content"></div>
    </div>
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</body>
</html>
```

### Step 2: Create Thymeleaf Fragment for Layout

**fragments/layout.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <div th:fragment="content">
        <!-- Content will be injected here -->
    </div>
</body>
</html>
```

### Step 3: Update Tab HTML Files

**tab1.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <div class="tab-content">
        <h2>Tab 1</h2>
        <form th:action="@{/tab/save}" th:object="${tabData}" method="post">
            <input type="hidden" th:field="*{id}"/>
            <div class="form-group">
                <label for="tab1Data">Tab 1 Data:</label>
                <input type="text" id="tab1Data" class="form-control" th:field="*{tab1Data}" required/>
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
            <button type="submit" formaction="/tab/2" class="btn btn-secondary">Next</button>
        </form>
    </div>
</body>
</html>
```

**tab2.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <div class="tab-content">
        <h2>Tab 2</h2>
        <form th:action="@{/tab/save}" th:object="${tabData}" method="post">
            <input type="hidden" th:field="*{id}"/>
            <div class="form-group">
                <label for="tab2Data">Tab 2 Data:</label>
                <input type="text" id="tab2Data" class="form-control" th:field="*{tab2Data}" required/>
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
            <button type="submit" formaction="/tab/3" class="btn btn-secondary">Next</button>
        </form>
    </div>
</body>
</html>
```

**tab3.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <div class="tab-content">
        <h2>Tab 3</h2>
        <form th:action="@{/tab/save}" th:object="${tabData}" method="post">
            <input type="hidden" th:field="*{id}"/>
            <div class="form-group">
                <label for="tab3Data">Tab 3 Data:</label>
                <input type="text" id="tab3Data" class="form-control" th:field="*{tab3Data}" required/>
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
        </form>
    </div>
</body>
</html>
```

### Step 4: Add Exception Handling

Create a global exception handler to handle any exceptions that might occur.

**GlobalExceptionHandler.java**
```java
package com.example.tabs.exception;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ModelAndView handleException(Exception ex, Model model) {
        ModelAndView modelAndView = new ModelAndView("error");
        model.addAttribute("message", ex.getMessage());
        return modelAndView;
    }
}
```

Create an error template to display the error message.

**error.html**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Error</title>
</head>
<body>
    <div class="container">
        <h1>An error occurred</h1>
        <p th:text="${message}"></p>
        <a href="/" class="btn btn-primary">Go to Home</a>
    </div>
</body>
</html>
```

### Step 5: Finalize the Application

**TabsApplication.java**
```java
package com.example.tabs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TabsApplication {

    public static void main(String[] args) {
        SpringApplication.run(TabsApplication.class, args);
    }
}
```

**TabController.java**
```java
package com.example.tabs.controller;

import com.example.tabs.model.TabData;
import com.example.tabs.service.TabDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequestMapping("/tab")
public class TabController {

    @Autowired
    private TabDataService tabDataService;

    @GetMapping("/{tabId}")
    public String getTab(@PathVariable int tabId, @RequestParam(required = false) Long id, Model model) {
        Optional<TabData> tabData = tabDataService.findById(id != null ? id : 1L);
        model.addAttribute("tabData", tabData.orElse(new TabData()));
        return "tab" + tabId;
    }

    @PostMapping("/save")
    public String saveTab(@ModelAttribute TabData tabData) {
        tabDataService.save(tabData);
        return "redirect:/tab/1?id=" + tabData.getId();
    }

    @PostMapping("/next")
    public String nextTab(@ModelAttribute TabData tabData) {
        tabDataService.save(tabData);
        return "redirect:/tab/2?id=" + tabData.getId();
    }
}
```

### Step 6: Run the Application

Run the Spring Boot application and navigate to `http://localhost:8080/tab/1` to see the tabs in action. You can fill in the form data, save it, and navigate through the tabs using the "Next" button. The data will be saved as a draft and loaded on the next page load. If any errors occur, they will be handled gracefully by the global exception handler.
