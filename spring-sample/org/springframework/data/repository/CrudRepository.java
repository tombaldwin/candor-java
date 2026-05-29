package org.springframework.data.repository;
public interface CrudRepository<T, ID> {
    <S extends T> S save(S entity);
    java.util.Optional<T> findById(ID id);
}
