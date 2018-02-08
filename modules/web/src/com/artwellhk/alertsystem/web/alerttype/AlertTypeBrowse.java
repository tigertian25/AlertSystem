package com.artwellhk.alertsystem.web.alerttype;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.EntityManager;

import com.artwellhk.alertsystem.entity.AlertType;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.cuba.core.entity.Entity;
import com.haulmont.cuba.gui.ComponentsHelper;
import com.haulmont.cuba.gui.components.Component;
import com.haulmont.cuba.gui.components.EntityCombinedScreen;
import com.haulmont.cuba.gui.components.FieldGroup;
import com.haulmont.cuba.gui.components.GroupTable;
import com.haulmont.cuba.gui.components.ListComponent;
import com.haulmont.cuba.gui.components.TabSheet;
import com.haulmont.cuba.gui.components.Table;
import com.haulmont.cuba.gui.components.Component.Validatable;
import com.haulmont.cuba.gui.data.CollectionDatasource;
import com.haulmont.cuba.gui.data.Datasource;
import com.haulmont.cuba.gui.data.GroupDatasource;
import com.vaadin.external.org.slf4j.Logger;
import com.vaadin.external.org.slf4j.LoggerFactory;

public class AlertTypeBrowse extends EntityCombinedScreen {
	Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
	private Logger log = LoggerFactory.getLogger(AlertTypeBrowse.class);
	 @Inject
	    protected GroupTable<AlertType> table;
	@Override
	public void init(Map<String, Object> params) {
		super.init(params);
	}
	@Override
	@SuppressWarnings("unchecked")
    protected void initBrowseItemChangeListener() {
        CollectionDatasource browseDs = getTable().getDatasource();
        Datasource editDs = getFieldGroup().getDatasource();
        browseDs.addItemChangeListener(e -> {
            if (e.getItem() != null) {
            	//AlertType alertType=(AlertType) e.getItem();
            	
                Entity reloadedItem = getDsContext().getDataSupplier().reload(e.getDs().getItem(), editDs.getView());
                AlertType alertType=(AlertType) reloadedItem;
                alertType.setAllowedDuration(alertType.getAllowedDuration()/60/1000);
                editDs.setItem(alertType);
//                editDs.setItem(reloadedItem);
                
            }
        });
    }
	@Override
	 @SuppressWarnings("unchecked")
	    public void save() {
	        FieldGroup fieldGroup = getFieldGroup();
	        List<Validatable> components = new ArrayList<>();
	        for (Component component: fieldGroup.getComponents()) {
	            if (component instanceof Validatable) {
	                components.add((Validatable)component);
	            }
	        }
	        if (!validate(components)) {
	            return;
	        }
	        getDsContext().commit();

	        ListComponent table = getTable();
	        CollectionDatasource browseDs = table.getDatasource();
	        Entity editedItem = fieldGroup.getDatasource().getItem();
	        AlertType alertType=(AlertType) editedItem;
	        alertType.setAllowedDuration(alertType.getAllowedDuration()*60*1000);
	        if (creating) {
	            browseDs.includeItem(alertType);
	        } else {
	            browseDs.updateItem(alertType);
	        }
	        table.setSelected(alertType);
//	        Set<AlertType> alertType= table.getSelected();
//	        for (AlertType alertType2 : alertType) {
//				
//	        	System.out.println("getAllowedDuration:"+alertType2.getAllowedDuration());
//			}
	        releaseLock();
	        disableEditControls();
	    }

}