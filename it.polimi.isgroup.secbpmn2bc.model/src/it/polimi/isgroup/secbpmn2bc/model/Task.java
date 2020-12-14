/**
 */
package it.polimi.isgroup.secbpmn2bc.model;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Task</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link it.polimi.isgroup.secbpmn2bc.model.Task#isOnChainExecution <em>On Chain Execution</em>}</li>
 * </ul>
 *
 * @see it.polimi.isgroup.secbpmn2bc.model.meta.SecBPMN2BCPackage#getTask()
 * @model
 * @generated
 */
public interface Task extends it.unitn.disi.sweng.secbpmn.model.Task {
	/**
	 * Returns the value of the '<em><b>On Chain Execution</b></em>' attribute.
	 * The default value is <code>"false"</code>.
	 * <!-- begin-user-doc -->
	 * <p>
	 * If the meaning of the '<em>On Chain Execution</em>' attribute isn't clear,
	 * there really should be more of a description here...
	 * </p>
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>On Chain Execution</em>' attribute.
	 * @see #isSetOnChainExecution()
	 * @see #unsetOnChainExecution()
	 * @see #setOnChainExecution(boolean)
	 * @see it.polimi.isgroup.secbpmn2bc.model.meta.SecBPMN2BCPackage#getTask_OnChainExecution()
	 * @model default="false" unsettable="true"
	 * @generated
	 */
	boolean isOnChainExecution();

	/**
	 * Sets the value of the '{@link it.polimi.isgroup.secbpmn2bc.model.Task#isOnChainExecution <em>On Chain Execution</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>On Chain Execution</em>' attribute.
	 * @see #isSetOnChainExecution()
	 * @see #unsetOnChainExecution()
	 * @see #isOnChainExecution()
	 * @generated
	 */
	void setOnChainExecution(boolean value);

	/**
	 * Unsets the value of the '{@link it.polimi.isgroup.secbpmn2bc.model.Task#isOnChainExecution <em>On Chain Execution</em>}' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #isSetOnChainExecution()
	 * @see #isOnChainExecution()
	 * @see #setOnChainExecution(boolean)
	 * @generated
	 */
	void unsetOnChainExecution();

	/**
	 * Returns whether the value of the '{@link it.polimi.isgroup.secbpmn2bc.model.Task#isOnChainExecution <em>On Chain Execution</em>}' attribute is set.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return whether the value of the '<em>On Chain Execution</em>' attribute is set.
	 * @see #unsetOnChainExecution()
	 * @see #isOnChainExecution()
	 * @see #setOnChainExecution(boolean)
	 * @generated
	 */
	boolean isSetOnChainExecution();

} // Task
