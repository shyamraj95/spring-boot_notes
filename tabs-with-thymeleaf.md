Certainly! You can combine the "Save to Draft" and "Next" functionality into a single button. When the button is clicked, it will save the current form data and then redirect to the next tab.

Here’s how to update the fragments to handle this:

1. Update the `MainController` to handle the next tab redirection after saving the form data.
2. Update the Thymeleaf fragments to include a single button for saving and navigating to the next tab.

### Updated Controller

**MainController.java**:
```java
package com.example.thymeleaftabs.controller;

import com.example.thymeleaftabs.entity.FormData;
import com.example.thymeleaftabs.service.FormDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequestMapping("/tab")
public class MainController {

    @Autowired
    private FormDataService formDataService;

    @GetMapping("/{tabId}")
    public String getTab(@PathVariable String tabId, Model model) {
        Optional<FormData> formData = formDataService.getFormData(tabId);
        model.addAttribute("tabId", tabId);
        model.addAttribute("formData", formData.orElse(new FormData()));
        return "main";
    }

    @PostMapping("/save")
    public String saveForm(@RequestParam String tabId, @RequestParam String content) {
        formDataService.saveFormData(tabId, content);
        int nextTabId = Integer.parseInt(tabId) + 1;
        if (nextTabId > 3) {
            nextTabId = 1; // Loop back to the first tab
        }
        return "redirect:/tab/" + nextTabId;
    }
}
```

### Updated Thymeleaf Fragments

**fragments/tab1.html**:
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<div th:fragment="tabContent(tabId, formData)">
    <form th:action="@{/tab/save}" method="post">
        <input type="hidden" name="tabId" th:value="${tabId}"/>
        <div class="form-group">
            <label for="content">Tab 1 Content</label>
            <textarea class="form-control" id="content" name="content" rows="3" th:text="${formData.content}"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Save and Next</button>
    </form>
</div>
</body>
</html>
```

**fragments/tab2.html**:
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<div th:fragment="tabContent(tabId, formData)">
    <form th:action="@{/tab/save}" method="post">
        <input type="hidden" name="tabId" th:value="${tabId}"/>
        <div class="form-group">
            <label for="content">Tab 2 Content</label>
            <textarea class="form-control" id="content" name="content" rows="3" th:text="${formData.content}"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Save and Next</button>
    </form>
</div>
</body>
</html>
```

**fragments/tab3.html**:
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<div th:fragment="tabContent(tabId, formData)">
    <form th:action="@{/tab/save}" method="post">
        <input type="hidden" name="tabId" th:value="${tabId}"/>
        <div class="form-group">
            <label for="content">Tab 3 Content</label>
            <textarea class="form-control" id="content" name="content" rows="3" th:text="${formData.content}"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Save and Next</button>
    </form>
</div>
</body>
</html>
```

**********************************************--------------------------------------***************************************************************************


### Step 1: Create a Spring Boot Project

Create a new Spring Boot project using Spring Initializr or your IDE with the following dependencies:
- Spring Web
- Thymeleaf
- Spring Data JPA
- H2 Database (or any other database of your choice)

### Step 2: Set up Thymeleaf Templates

First, create a main layout template that includes the vertical pills tabs.

**src/main/resources/templates/layout.html**:
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Vertical Pills Tabs</title>
    <link rel="stylesheet" th:href="@{/css/bootstrap.min.css}" />
    <style>
        .nav-pills .nav-link {
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-3">
            <div class="nav flex-column nav-pills" id="v-pills-tab" role="tablist" aria-orientation="vertical">
                <a class="nav-link" th:classappend="${activeTab == 1} ? 'active' : ''" id="v-pills-tab1-tab" href="#" th:href="@{/tab/1}">Tab 1</a>
                <a class="nav-link" th:classappend="${activeTab == 2} ? 'active' : ''" id="v-pills-tab2-tab" href="#" th:href="@{/tab/2}">Tab 2</a>
                <a class="nav-link" th:classappend="${activeTab == 3} ? 'active' : ''" id="v-pills-tab3-tab" href="#" th:href="@{/tab/3}">Tab 3</a>
            </div>
        </div>
        <div class="col-9">
            <div class="tab-content" id="v-pills-tabContent">
                <div th:replace="::${tabContent}"></div>
            </div>
        </div>
    </div>
</div>
<script th:src="@{/js/bootstrap.bundle.min.js}"></script>
</body>
</html>
```

### Step 3: Create Controller and Service

Create a `DraftService` to handle saving and retrieving draft data, and a `TabController` to handle the requests.

**src/main/java/com/example/demo/service/DraftService.java**:
```java
package com.example.demo.service;

import com.example.demo.model.Draft;
import com.example.demo.repository.DraftRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DraftService {

    @Autowired
    private DraftRepository draftRepository;

    public Draft saveDraft(Draft draft) {
        return draftRepository.save(draft);
    }

    public Optional<Draft> getDraftByTabId(int tabId) {
        return draftRepository.findByTabId(tabId);
    }
}
```

**src/main/java/com/example/demo/controller/TabController.java**:
```java
package com.example.demo.controller;

import com.example.demo.model.Draft;
import com.example.demo.service.DraftService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
public class TabController {

    @Autowired
    private DraftService draftService;

    @GetMapping("/tab/{id}")
    public String getTab(@PathVariable int id, Model model) {
        model.addAttribute("activeTab", id);
        Optional<Draft> draftOpt = draftService.getDraftByTabId(id);
        draftOpt.ifPresent(draft -> model.addAttribute("draft", draft));
        model.addAttribute("tabContent", "tabs/tab" + id + " :: content");
        return "layout";
    }

    @PostMapping("/tab/{id}/save")
    public String saveDraft(@PathVariable int id, @RequestParam String content) {
        Draft draft = new Draft(id, content);
        draftService.saveDraft(draft);
        return "redirect:/tab/" + id;
    }
}
```

### Step 4: Create HTML Pages for Tabs

Create separate HTML fragments for each tab.

**src/main/resources/templates/tabs/tab1.html**:
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Tab 1</title>
</head>
<body>
<div th:fragment="content">
    <h2>Tab 1</h2>
    <form th:action="@{/tab/1/save}" method="post">
        <div class="form-group">
            <label for="content">Content</label>
            <textarea class="form-control" id="content" name="content" th:text="${draft != null} ? ${draft.content} : ''"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Save to Draft</button>
        <a th:href="@{/tab/2}" class="btn btn-secondary">Next</a>
    </form>
</div>
</body>
</html>
```

Similarly, create `tab2.html` and `tab3.html` with appropriate modifications.

### Step 5: Implement Draft Saving and Retrieval

Create the `Draft` entity and repository.

**src/main/java/com/example/demo/model/Draft.java**:
```java
package com.example.demo.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Draft {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private int tabId;
    private String content;

    // Constructors, getters and setters

    public Draft() {
    }

    public Draft(int tabId, String content) {
        this.tabId = tabId;
        this.content = content;
    }

    // Getters and Setters
}
```

**src/main/java/com/example/demo/repository/DraftRepository.java**:
```java
package com.example.demo.repository;

import com.example.demo.model.Draft;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface DraftRepository extends CrudRepository<Draft, Long> {
    Optional<Draft> findByTabId(int tabId);
}
```

### Application Properties

Configure your application properties for the database connection.

**src/main/resources/application.properties**:
```properties
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.h2.console.enabled=true
```
*********************************************-------------------------------------***********************************************************




 <div  class="col-sm-6">
        <h3>Left Tabs</h3>
        <hr/>
        <div class="col-xs-3"> <!-- required for floating -->
          <!-- Nav tabs -->
          <ul class="nav nav-tabs tabs-left sideways">
            <li class="active"><a href="#home-v" data-toggle="tab">Home</a></li>
            <li><a href="#profile-v" data-toggle="tab">Profile</a></li>
            <li><a href="#messages-v" data-toggle="tab">Messages</a></li>
            <li><a href="#settings-v" data-toggle="tab">Settings</a></li>
          </ul>
        </div>

        <div class="col-xs-9">
          <!-- Tab panes -->
          <div class="tab-content">
            <div class="tab-pane active" id="home-v">Home Tab.</div>
            <div class="tab-pane" id="profile-v">Profile Tab.</div>
            <div class="tab-pane" id="messages-v">Messages Tab.</div>
            <div class="tab-pane" id="settings-v">Settings Tab.</div>
          </div>
        </div>

        <div class="clearfix"></div>

      </div>


      .tabs-left {
  border-bottom: none;
  border-right: 1px solid #ddd;
}

.tabs-left>li {
  float: none;
 margin:0px;
  
}

.tabs-left>li.active>a,
.tabs-left>li.active>a:hover,
.tabs-left>li.active>a:focus {
  border-bottom-color: #ddd;
  border-right-color: transparent;
  background:#f90;
  border:none;
  border-radius:0px;
  margin:0px;
}
.nav-tabs>li>a:hover {
    /* margin-right: 2px; */
    line-height: 1.42857143;
    border: 1px solid transparent;
    /* border-radius: 4px 4px 0 0; */
}
.tabs-left>li.active>a::after{content: "";
    position: absolute;
    top: 10px;
    right: -10px;
    border-top: 10px solid transparent;
  border-bottom: 10px solid transparent;
  
  border-left: 10px solid #f90;
    display: block;
    width: 0;}
