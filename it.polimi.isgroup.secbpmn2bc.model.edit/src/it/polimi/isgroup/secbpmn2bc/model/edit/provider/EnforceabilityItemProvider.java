/**
 */
package it.polimi.isgroup.secbpmn2bc.model.edit.provider;

import it.polimi.isgroup.secbpmn2bc.model.Enforceability;

import it.polimi.isgroup.secbpmn2bc.model.edit.internal.Activator;

import it.polimi.isgroup.secbpmn2bc.model.meta.SecBPMN2BCFactory;

import it.polimi.isgroup.secbpmn2bc.model.meta.SecBPMN2BCPackage;
import it.unitn.disi.sweng.gmt.model.meta.GMTPackage;

import it.unitn.disi.sweng.secbpmn.model.edit.provider.SecurityAnnotationItemProvider;

import java.util.Collection;
import java.util.List;

import org.eclipse.emf.common.notify.AdapterFactory;
import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.common.util.ResourceLocator;

import org.eclipse.emf.edit.provider.ComposeableAdapterFactory;
import org.eclipse.emf.edit.provider.IItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.ItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.ViewerNotification;

/**
 * This is the item provider adapter for a {@link it.polimi.isgroup.secbpmn2bc.model.Enforceability} object.
 * <!-- begin-user-doc -->
 * <!-- end-user-doc -->
 * @generated
 */
public class EnforceabilityItemProvider extends SecurityAnnotationItemProvider {
	/**
	 * This constructs an instance from a factory and a notifier.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EnforceabilityItemProvider(AdapterFactory adapterFactory) {
		super(adapterFactory);
	}

	/**
	 * This returns the property descriptors for the adapted class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public List<IItemPropertyDescriptor> getPropertyDescriptors(Object object) {
		if (itemPropertyDescriptors == null) {
			super.getPropertyDescriptors(object);

			addScopePropertyDescriptor(object);
			addUserDefinedUsersPropertyDescriptor(object);
		}
		return itemPropertyDescriptors;
	}

	/**
	 * This adds a property descriptor for the Scope feature.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected void addScopePropertyDescriptor(Object object) {
		itemPropertyDescriptors
				.add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
						getResourceLocator(), getString("_UI_Enforceability_Scope_feature"), //$NON-NLS-1$
						getString("_UI_PropertyDescriptor_description", "_UI_Enforceability_Scope_feature", //$NON-NLS-1$//$NON-NLS-2$
								"_UI_Enforceability_type"), //$NON-NLS-1$
						SecBPMN2BCPackage.Literals.ENFORCEABILITY__SCOPE, true, false, false,
						ItemPropertyDescriptor.GENERIC_VALUE_IMAGE, null, null));
	}

	/**
	 * This adds a property descriptor for the User Defined Users feature.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected void addUserDefinedUsersPropertyDescriptor(Object object) {
		itemPropertyDescriptors.add(createItemPropertyDescriptor(
				((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(), getResourceLocator(),
				getString("_UI_Enforceability_UserDefinedUsers_feature"), //$NON-NLS-1$
				getString("_UI_PropertyDescriptor_description", "_UI_Enforceability_UserDefinedUsers_feature", //$NON-NLS-1$//$NON-NLS-2$
						"_UI_Enforceability_type"), //$NON-NLS-1$
				SecBPMN2BCPackage.Literals.ENFORCEABILITY__USER_DEFINED_USERS, true, false, true, null, null, null));
	}

	/**
	 * This returns Enforceability.gif.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object getImage(Object object) {
		return overlayImage(object, getResourceLocator().getImage("full/obj16/Enforceability")); //$NON-NLS-1$
	}

	/**
	 * This returns the label text for the adapted class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public String getText(Object object) {
		String label = ((Enforceability) object).getUuid();
		return label == null || label.length() == 0 ? getString("_UI_Enforceability_type") : //$NON-NLS-1$
				getString("_UI_Enforceability_type") + " " + label; //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * This handles model notifications by calling {@link #updateChildren} to update any cached
	 * children and by creating a viewer notification, which it passes to {@link #fireNotifyChanged}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void notifyChanged(Notification notification) {
		updateChildren(notification);

		switch (notification.getFeatureID(Enforceability.class)) {
		case SecBPMN2BCPackage.ENFORCEABILITY__SCOPE:
			fireNotifyChanged(new ViewerNotification(notification, notification.getNotifier(), false, true));
			return;
		}
		super.notifyChanged(notification);
	}

	/**
	 * This adds {@link org.eclipse.emf.edit.command.CommandParameter}s describing the children
	 * that can be created under this object.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected void collectNewChildDescriptors(Collection<Object> newChildDescriptors, Object object) {
		super.collectNewChildDescriptors(newChildDescriptors, object);

		newChildDescriptors.add(createChildParameter(GMTPackage.Literals.GMT_NODE__NODES,
				SecBPMN2BCFactory.eINSTANCE.createPrivitySphere()));

		newChildDescriptors.add(createChildParameter(GMTPackage.Literals.GMT_NODE__NODES,
				SecBPMN2BCFactory.eINSTANCE.createEnforceability()));

		newChildDescriptors.add(
				createChildParameter(GMTPackage.Literals.GMT_NODE__NODES, SecBPMN2BCFactory.eINSTANCE.createProcess()));

		newChildDescriptors.add(createChildParameter(GMTPackage.Literals.GMT_NODE__NODES,
				SecBPMN2BCFactory.eINSTANCE.createDataItems()));

		newChildDescriptors.add(
				createChildParameter(GMTPackage.Literals.GMT_NODE__NODES, SecBPMN2BCFactory.eINSTANCE.createTask()));

		newChildDescriptors.add(
				createChildParameter(GMTPackage.Literals.GMT_NODE__NODES, SecBPMN2BCFactory.eINSTANCE.createGroup()));

		newChildDescriptors.add(createChildParameter(GMTPackage.Literals.GMT_NODE__NODES,
				SecBPMN2BCFactory.eINSTANCE.createDefinitions()));
	}

	/**
	 * Return the resource locator for this item provider's resources.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public ResourceLocator getResourceLocator() {
		return Activator.INSTANCE;
	}

}
