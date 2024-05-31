Soft Delete Parent and Child Entities in Spring Boot with JPA
:sectnums:
:toc:

== Background

The need to perform soft deletes arises to retain data for future auditing, undelete options, or historical purposes. Soft deletes involve marking records as deleted without physically removing them from the database. In this context, we need to ensure that both parent and child entities are marked as deleted in a cascading manner.

== Requirements

Must Have:

Ability to soft delete a parent entity and all its associated child entities.
Ensure cascading soft delete operation using JPA repository.
Override the default delete method in the JPA repository.
Custom findById implementation to exclude soft-deleted entities.
findAll method to exclude soft-deleted entities.
Should Have:

Soft delete flag (isDeleted) implementation.
Avoid physical deletion of records.
== Method

Step 1: Define BaseEntity with Soft Delete Flag
Create an abstract base entity class that includes the soft delete flag and implements common functionality.

java
Copy code
import org.hibernate.annotations.Where;
import javax.persistence.*;

@MappedSuperclass
@EntityListeners(SoftDeleteListener.class)
@Where(clause = "is_deleted = false")
public abstract class BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "is_deleted")
    private boolean isDeleted = false;

    // Getters and setters
}
Step 2: Define Parent and Child Entities Extending BaseEntity
Make your entities extend the BaseEntity class to inherit the soft delete functionality.

java
Copy code
@Entity
public class Parent extends BaseEntity {
    private String name;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL)
    private List<Child> children;

    // Getters and setters
}

@Entity
public class Child extends BaseEntity {
    private String name;

    @ManyToOne
    @JoinColumn(name = "parent_id")
    private Parent parent;

    // Getters and setters
}
Step 3: Implement SoftDeleteListener
Create a listener to handle the soft delete logic for cascading operations.

java
Copy code
import javax.persistence.*;

public class SoftDeleteListener {

    @PreRemove
    private void preRemove(BaseEntity entity) {
        entity.setIsDeleted(true);
        if (entity instanceof Parent) {
            for (Child child : ((Parent) entity).getChildren()) {
                child.setIsDeleted(true);
            }
        }
    }
}
Step 4: Create Generic Soft Delete Repository
Create a base repository interface for soft delete operations.

java
Copy code
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

@NoRepositoryBean
public interface SoftDeleteRepository<T extends BaseEntity, ID> extends JpaRepository<T, ID> {

    @Override
    @Modifying
    @Transactional
    @Query("UPDATE #{#entityName} e SET e.isDeleted = true WHERE e.id = :id")
    void deleteById(@Param("id") ID id);

    @Override
    @Modifying
    @Transactional
    default void delete(T entity) {
        entity.setIsDeleted(true);
        save(entity);
    }
}
Step 5: Extend Generic Repository for Entities
Extend the generic SoftDeleteRepository for your specific entities.

java
Copy code
import org.springframework.stereotype.Repository;

@Repository
public interface ParentRepository extends SoftDeleteRepository<Parent, Long> {
}

@Repository
public interface ChildRepository extends SoftDeleteRepository<Child, Long> {
}
Step 6: Service Layer Implementation
Implement the service layer to handle the cascading soft delete logic.

java
Copy code
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ParentService {
    @Autowired
    private ParentRepository parentRepository;

    @Transactional
    public void softDeleteParent(Long parentId) {
        Parent parent = parentRepository.findById(parentId).orElseThrow(() -> new RuntimeException("Parent not found"));
        parentRepository.delete(parent);
    }

    public Optional<Parent> findById(Long id) {
        return parentRepository.findById(id);
    }

    public List<Parent> findAll() {
        return parentRepository.findAll();
    }
}
== Implementation

Define Base Entity: Create a BaseEntity class with the isDeleted flag and common functionality.
Define Specific Entities: Extend BaseEntity for Parent and Child entities.
Listener Creation: Implement SoftDeleteListener to handle cascading soft delete logic.
Repository Customization: Create a generic SoftDeleteRepository for soft delete operations.
Service Implementation: Implement and test the service layer for cascading soft deletes and ensure that standard findById and findAll methods work as expected.
== Milestones

Entity Update: Define the BaseEntity class and extend it for Parent and Child entities.
Listener Creation: Implement the SoftDeleteListener.
Repository Extension: Create and extend the SoftDeleteRepository for the entities.
Service Implementation: Implement and test the service layer for cascading soft deletes.
Integration Testing: Ensure the solution works as expected through comprehensive integration tests.
== Gathering Results

Evaluate the implementation by checking:

Parent and child entities are correctly marked as deleted in the database.
Standard findById and findAll methods exclude soft-deleted entities.
No physical deletion occurs in the database.









/////////////////////////////%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%/////////////////////////////////////////////////

To implement soft delete functionality in Spring Boot by overriding methods in `CrudRepository` or `PagingAndSortingRepository`, you need to adjust the default query methods to exclude entities marked as deleted. Here’s how you can achieve that:

### Step-by-Step Guide

1. **Add a `deleted` field to your entities**:
   Include a boolean field `deleted` in your entities to indicate whether they are deleted.

2. **Extend `CrudRepository` or `PagingAndSortingRepository`**:
   Override the default methods to include filtering for the `deleted` field.

3. **Custom Repository Implementation**:
   Create a custom base repository to handle common query logic for soft delete.

### Example

#### 1. Entity Definitions

**Parent Entity:**

```java
import javax.persistence.*;
import java.util.List;

@Entity
public class Parent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Child> children;

    // Getters and setters
}
```

**Child Entity:**

```java
import javax.persistence.*;

@Entity
public class Child {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @ManyToOne
    @JoinColumn(name = "parent_id")
    private Parent parent;

    // Getters and setters
}
```

#### 2. Custom Repository Implementation

**Custom Base Repository Interface:**

```java
import java.util.Optional;

public interface SoftDeleteRepository<T, ID> extends CrudRepository<T, ID> {
    Optional<T> findByIdAndDeletedFalse(ID id);
    Iterable<T> findAllByDeletedFalse();
}
```

**Custom Base Repository Implementation:**

```java
import org.springframework.data.repository.CrudRepository;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.util.Optional;

public class SoftDeleteRepositoryImpl<T, ID extends Serializable> implements SoftDeleteRepository<T, ID> {
    
    private final CrudRepository<T, ID> repository;

    public SoftDeleteRepositoryImpl(CrudRepository<T, ID> repository) {
        this.repository = repository;
    }

    @Override
    public Optional<T> findByIdAndDeletedFalse(ID id) {
        return repository.findById(id).filter(entity -> !((SoftDeletable) entity).isDeleted());
    }

    @Override
    public Iterable<T> findAllByDeletedFalse() {
        return repository.findAll().stream().filter(entity -> !((SoftDeletable) entity).isDeleted()).toList();
    }

    @Override
    @Transactional
    public <S extends T> S save(S entity) {
        return repository.save(entity);
    }

    @Override
    public <S extends T> Iterable<S> saveAll(Iterable<S> entities) {
        return repository.saveAll(entities);
    }

    @Override
    public Optional<T> findById(ID id) {
        return repository.findById(id);
    }

    @Override
    public boolean existsById(ID id) {
        return repository.existsById(id);
    }

    @Override
    public Iterable<T> findAll() {
        return repository.findAll();
    }

    @Override
    public Iterable<T> findAllById(Iterable<ID> ids) {
        return repository.findAllById(ids);
    }

    @Override
    public long count() {
        return repository.count();
    }

    @Override
    public void deleteById(ID id) {
        repository.deleteById(id);
    }

    @Override
    public void delete(T entity) {
        repository.delete(entity);
    }

    @Override
    public void deleteAllById(Iterable<? extends ID> ids) {
        repository.deleteAllById(ids);
    }

    @Override
    public void deleteAll(Iterable<? extends T> entities) {
        repository.deleteAll(entities);
    }

    @Override
    public void deleteAll() {
        repository.deleteAll();
    }
}
```

**SoftDeletable Interface:**

```java
public interface SoftDeletable {
    boolean isDeleted();
}
```

**Implement SoftDeletable in Entities:**

```java
@Entity
public class Parent implements SoftDeletable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Child> children;

    @Override
    public boolean isDeleted() {
        return deleted;
    }

    public void setDeleted(boolean deleted) {
        this.deleted = deleted;
    }

    // Other getters and setters
}
```

```java
@Entity
public class Child implements SoftDeletable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @ManyToOne
    @JoinColumn(name = "parent_id")
    private Parent parent;

    @Override
    public boolean isDeleted() {
        return deleted;
    }

    public void setDeleted(boolean deleted) {
        this.deleted = deleted;
    }

    // Other getters and setters
}
```

**Repository Interfaces:**

```java
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ParentRepository extends SoftDeleteRepository<Parent, Long> {
}

@Repository
public interface ChildRepository extends SoftDeleteRepository<Child, Long> {
}
```

#### 3. Service Layer

**Parent Service:**

```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class ParentService {

    @Autowired
    private ParentRepository parentRepository;

    @Transactional
    public void softDeleteParent(Long parentId) {
        Optional<Parent> parentOptional = parentRepository.findById(parentId);
        if (parentOptional.isPresent()) {
            Parent parent = parentOptional.get();
            parent.setDeleted(true);
            for (Child child : parent.getChildren()) {
                child.setDeleted(true);
            }
            parentRepository.save(parent);
        }
    }

    public Iterable<Parent> findAllActiveParents() {
        return parentRepository.findAllByDeletedFalse();
    }
}
```

### Summary

1. **Entities**: Add a `deleted` field and implement a `SoftDeletable` interface.
2. **Custom Repository**: Create a custom repository interface and implementation to handle soft delete logic.
3. **Service**: Implement a method to mark the parent and its children as deleted.
4. **Controller**: Expose endpoints to fetch non-deleted entities and perform soft deletes.

This structure provides a clean and reusable approach to handle soft delete functionality with cascading behavior in Spring Boot using JPA.


////////////

this approach will work for entities with orphanRemoval = true. The orphanRemoval attribute is used to automatically remove child entities when they are no longer referenced by their parent. However, since we're implementing a soft delete (marking entities as deleted rather than actually removing them), we need to ensure that child entities are also marked as deleted when their parent is soft deleted.

Here's how you can achieve this:

Entities: Ensure that the deleted field is present and properly mapped.
Repository Methods: Use @Query annotations to exclude deleted entities.
Service Layer: Implement the soft delete logic to handle the deleted field and cascade the soft delete to child entities.
Example
1. Entity Definitions
Parent Entity:

java
Copy code
import javax.persistence.*;
import java.util.List;

@Entity
public class Parent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Child> children;

    // Getters and setters
}
Child Entity:

java
Copy code
import javax.persistence.*;

@Entity
public class Child {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private boolean deleted = false;

    @ManyToOne
    @JoinColumn(name = "parent_id")
    private Parent parent;

    // Getters and setters
}
2. Repository Interfaces
Parent Repository:

java
Copy code
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ParentRepository extends JpaRepository<Parent, Long> {
    
    @Query("SELECT p FROM Parent p WHERE p.deleted = false")
    List<Parent> findAllByDeletedFalse();

    @Query("SELECT p FROM Parent p WHERE p.id = :id AND p.deleted = false")
    Optional<Parent> findByIdAndDeletedFalse(Long id);
}
Child Repository:

java
Copy code
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ChildRepository extends JpaRepository<Child, Long> {
    
    @Query("SELECT c FROM Child c WHERE c.deleted = false")
    List<Child> findAllByDeletedFalse();

    @Query("SELECT c FROM Child c WHERE c.id = :id AND c.deleted = false")
    Optional<Child> findByIdAndDeletedFalse(Long id);

    @Query("SELECT c FROM Child c WHERE c.parent.id = :parentId AND c.deleted = false")
    List<Child> findAllByParentIdAndDeletedFalse(Long parentId);
}
3. Service Layer
Parent Service:

java
Copy code
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class ParentService {

    @Autowired
    private ParentRepository parentRepository;

    @Autowired
    private ChildRepository childRepository;

    @Transactional
    public void softDeleteParent(Long parentId) {
        Optional<Parent> parentOptional = parentRepository.findById(parentId);
        if (parentOptional.isPresent()) {
            Parent parent = parentOptional.get();
            parent.setDeleted(true);
            parent.getChildren().forEach(child -> child.setDeleted(true));
            parentRepository.save(parent);
        }
    }

    public List<Parent> findAllActiveParents() {
        return parentRepository.findAllByDeletedFalse();
    }

    public Optional<Parent> findActiveParentById(Long id) {
        return parentRepository.findByIdAndDeletedFalse(id);
    }
}
Child Service (Optional):

java
Copy code
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class ChildService {

    @Autowired
    private ChildRepository childRepository;

    public List<Child> findAllActiveChildren() {
        return childRepository.findAllByDeletedFalse();
    }

    public Optional<Child> findActiveChildById(Long id) {
        return childRepository.findByIdAndDeletedFalse(id);
    }

    public List<Child> findActiveChildrenByParentId(Long parentId) {
        return childRepository.findAllByParentIdAndDeletedFalse(parentId);
    }
}
Summary
Entities: Ensure the deleted field is present.
Repository Methods: Use @Query annotations to filter out deleted entities.
Service Layer: Implement the soft delete logic to handle the deleted field and cascade the soft delete to child entities.
This approach ensures that when you soft delete a parent entity, all its child entities are also soft deleted, and the orphanRemoval feature will work correctly by marking the children as deleted without physically removing them from the database.
