package org.securegraph.property;

import org.securegraph.Authorizations;
import org.securegraph.Visibility;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MutablePropertyImpl extends MutableProperty {
    private final String key;
    private final String name;
    private Set<Visibility> hiddenVisibilities;
    private Object value;
    private Visibility visibility;
    private final Map<String, Object> metadata;

    public MutablePropertyImpl(String key, String name, Object value, Map<String, Object> metadata, Set<Visibility> hiddenVisibilities, Visibility visibility) {
        if (metadata == null) {
            metadata = new HashMap<String, Object>();
        }

        this.key = key;
        this.name = name;
        this.value = value;
        this.metadata = metadata;
        this.visibility = visibility;
        this.hiddenVisibilities = hiddenVisibilities;
    }

    public String getKey() {
        return key;
    }

    public String getName() {
        return name;
    }

    public Object getValue() {
        return value;
    }

    public Visibility getVisibility() {
        return visibility;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    @Override
    public Iterable<Visibility> getHiddenVisibilities() {
        return this.hiddenVisibilities;
    }

    @Override
    public boolean isHidden(Authorizations authorizations) {
        if (hiddenVisibilities != null) {
            for (Visibility v : getHiddenVisibilities()) {
                if (authorizations.canRead(v)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public void setVisibility(Visibility visibility) {
        this.visibility = visibility;
    }

    @Override
    public void addHiddenVisibility(Visibility visibility) {
        if (this.hiddenVisibilities == null) {
            this.hiddenVisibilities = new HashSet<Visibility>();
        }
        this.hiddenVisibilities.add(visibility);
    }
}
