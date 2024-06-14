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


#### `tab2.html` (with dynamic form rows including input and dropdown)

```html
<!-- src/main/resources/templates/fragments/tab2.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<div th:fragment="tab2">
    <form th:action="@{/tabs/save}" method="post" id="tab2Form">
        <input type="hidden" name="tabId" value="2">
        <input type="hidden" name="appId" th:value="${appId}">
        <div id="dynamic-form-rows">
            <div class="form-row">
                <div class="form-group col-md-4">
                    <label for="inputData">Input Data</label>
                    <input type="text" class="form-control" name="inputData[]" placeholder="Enter data">
                </div>
                <div class="form-group col-md-4">
                    <label for="dropdownData">Dropdown Data</label>
                    <select class="form-control" name="dropdownData[]">
                        <option value="Option1">Option 1</option>
                        <option value="Option2">Option 2</option>
                        <option value="Option3">Option 3</option>
                    </select>
                </div>
                <div class="form-group col-md-2">
                    <label>&nbsp;</label>
                    <button type="button" class="btn btn-success btn-block" onclick="addFormRow()">+</button>
                </div>
                <div class="form-group col-md-2">
                    <label>&nbsp;</label>
                    <button type="button" class="btn btn-danger btn-block" onclick="removeFormRow(this)">-</button>
                </div>
            </div>
        </div>
        <button type="submit" class="btn btn-primary">Save to Draft</button>
        <button type="button" class="btn btn-secondary" onclick="nextTab(3)">Next</button>
    </form>
</div>

<script>
    function addFormRow() {
        let formRow = `
            <div class="form-row">
                <div class="form-group col-md-4">
                    <input type="text" class="form-control" name="inputData[]" placeholder="Enter data">
                </div>
                <div class="form-group col-md-4">
                    <select class="form-control" name="dropdownData[]">
                        <option value="Option1">Option 1</option>
                        <option value="Option2">Option 2</option>
                        <option value="Option3">Option 3</option>
                    </select>
                </div>
                <div class="form-group col-md-2">
                    <button type="button" class="btn btn-success btn-block" onclick="addFormRow()">+</button>
                </div>
                <div class="form-group col-md-2">
                    <button type="button" class="btn btn-danger btn-block" onclick="removeFormRow(this)">-</button>
                </div>
            </div>`;
        $('#dynamic-form-rows').append(formRow);
    }

    function removeFormRow(button) {
        $(button).closest('.form-row').remove();
    }
</script>
</html>
```

### Step 2: Update the Controller

Update the controller to handle lists of input and dropdown data for tab 2.

```java
// src/main/java/com/example/demo/controller/TabController.java
package com.example.demo.controller;

import com.example.demo.model.TabData;
import com.example.demo.repository.TabDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/tabs")
public class TabController {

    @Autowired
    private TabDataRepository tabDataRepository;

    @GetMapping
    public String getTabs(@RequestParam(required = false) Integer tabId, @RequestParam(required = false) String appId, Model model) {
        model.addAttribute("tabId", tabId);
        model.addAttribute("appId", appId);

        if (tabId != null && appId != null) {
            Optional<TabData> optionalTabData = tabDataRepository.findByTabIdAndAppId(tabId, appId);
            optionalTabData.ifPresent(tabData -> model.addAttribute("formData", tabData.getFormData()));
        }

        return "tabs";
    }

    @PostMapping("/save")
    public String saveTabData(@RequestParam int tabId, @RequestParam String appId, 
                              @RequestParam List<String> inputData, @RequestParam List<String> dropdownData) {
        Optional<TabData> optionalTabData = tabDataRepository.findByTabIdAndAppId(tabId, appId);
        TabData tabData;
        if (optionalTabData.isPresent()) {
            tabData = optionalTabData.get();
        } else {
            tabData = new TabData();
            tabData.setTabId(tabId);
            tabData.setAppId(appId);
        }
        StringBuilder formData = new StringBuilder();
        for (int i = 0; i < inputData.size(); i++) {
            formData.append(inputData.get(i)).append(":").append(dropdownData.get(i)).append(";");
        }
        tabData.setFormData(formData.toString());
        tabDataRepository.save(tabData);
        return "redirect:/tabs?tabId=" + tabId + "&appId=" + appId;
    }
}
```

### Step 3: Main Template for Vertical Tabs

Modify `tabs.html` to include Thymeleaf fragments for each tab.

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Tabs Example</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="row">
            <div class="col-3">
                <div class="nav flex-column nav-pills" id="v-pills-tab" role="tablist" aria-orientation="vertical">
                    <a class="nav-link" th:classappend="${tabId == 1} ? 'active'" id="v-pills-tab1-tab" href="#v-pills-tab1" role="tab">Tab 1</a>
                    <a class="nav-link" th:classappend="${tabId == 2} ? 'active'" id="v-pills-tab2-tab" href="#v-pills-tab2" role="tab">Tab 2</a>
                    <a class="nav-link" th:classappend="${tabId == 3} ? 'active'" id="v-pills-tab3-tab" href="#v-pills-tab3" role="tab">Tab 3</a>
                </div>
            </div>
            <div class="col-9">
                <div class="tab-content" id="v-pills-tabContent">
                    <div class="tab-pane fade" th:classappend="${tabId == 1} ? 'show active'" id="v-pills-tab1" role="tabpanel" th:replace="fragments/tab1 :: tab1"></div>
                    <div class="tab-pane fade" th:classappend="${tabId == 2} ? 'show active'" id="v-pills-tab2" role="tabpanel" th:replace="fragments/tab2 :: tab2"></div>
                    <div class="tab-pane fade" th:classappend="${tabId == 3} ? 'show active'" id="v-pills-tab3" role="tabpanel" th:replace="fragments/tab3 :: tab3"></div>
                </div>
            </div>
        </div>
    </div>
    <script>
        function nextTab(tabId) {
            const urlParams = new URLSearchParams(window.location.search);
            const appId = urlParams.get('appId');
            window.location.href = `/tabs?tabId=${tabId}&appId=${appId}`;
        }
    </script>
</body>
</html>
```


+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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
https://www.tutorialrepublic.com/codelab.php?topic=bootstrap&file=table-with-add-and-delete-row-feature
https://stackoverflow.com/questions/34057947/adding-row-on-click-in-bootstrap-form
