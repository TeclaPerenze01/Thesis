/**
 */
package it.polimi.isgroup.secbpmn2bc.model.impl;

import it.polimi.isgroup.secbpmn2bc.model.DataItems;
import it.polimi.isgroup.secbpmn2bc.model.OnChainData;

import it.polimi.isgroup.secbpmn2bc.model.meta.SecBPMN2BCPackage;

import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.ecore.EClass;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Data Items</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link it.polimi.isgroup.secbpmn2bc.model.impl.DataItemsImpl#getOnChainData <em>On Chain Data</em>}</li>
 * </ul>
 *
 * @generated
 */
public class DataItemsImpl extends it.unitn.disi.sweng.secbpmn.model.impl.DataItemsImpl implements DataItems {
	/**
	 * The default value of the '{@link #getOnChainData() <em>On Chain Data</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getOnChainData()
	 * @generated
	 * @ordered
	 */
	protected static final OnChainData ON_CHAIN_DATA_EDEFAULT = OnChainData.DIGEST;

	/**
	 * The cached value of the '{@link #getOnChainData() <em>On Chain Data</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getOnChainData()
	 * @generated
	 * @ordered
	 */
	protected OnChainData onChainData = ON_CHAIN_DATA_EDEFAULT;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected DataItemsImpl() {
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EClass eStaticClass() {
		return SecBPMN2BCPackage.Literals.DATA_ITEMS;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public OnChainData getOnChainData() {
		return onChainData;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void setOnChainData(OnChainData newOnChainData) {
		OnChainData oldOnChainData = onChainData;
		onChainData = newOnChainData == null ? ON_CHAIN_DATA_EDEFAULT : newOnChainData;
		if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, SecBPMN2BCPackage.DATA_ITEMS__ON_CHAIN_DATA,
					oldOnChainData, onChainData));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object eGet(int featureID, boolean resolve, boolean coreType) {
		switch (featureID) {
		case SecBPMN2BCPackage.DATA_ITEMS__ON_CHAIN_DATA:
			return getOnChainData();
		}
		return super.eGet(featureID, resolve, coreType);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eSet(int featureID, Object newValue) {
		switch (featureID) {
		case SecBPMN2BCPackage.DATA_ITEMS__ON_CHAIN_DATA:
			setOnChainData((OnChainData) newValue);
			return;
		}
		super.eSet(featureID, newValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eUnset(int featureID) {
		switch (featureID) {
		case SecBPMN2BCPackage.DATA_ITEMS__ON_CHAIN_DATA:
			setOnChainData(ON_CHAIN_DATA_EDEFAULT);
			return;
		}
		super.eUnset(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public boolean eIsSet(int featureID) {
		switch (featureID) {
		case SecBPMN2BCPackage.DATA_ITEMS__ON_CHAIN_DATA:
			return onChainData != ON_CHAIN_DATA_EDEFAULT;
		}
		return super.eIsSet(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public String toString() {
		if (eIsProxy())
			return super.toString();

		StringBuffer result = new StringBuffer(super.toString());
		result.append(" (OnChainData: "); //$NON-NLS-1$
		result.append(onChainData);
		result.append(')');
		return result.toString();
	}

} //DataItemsImpl
