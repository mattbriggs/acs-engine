package compute

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"net/http"
)

// VirtualMachineScaleSetRollingUpgradesClient is the compute Client
type VirtualMachineScaleSetRollingUpgradesClient struct {
	ManagementClient
}

// NewVirtualMachineScaleSetRollingUpgradesClient creates an instance of the
// VirtualMachineScaleSetRollingUpgradesClient client.
func NewVirtualMachineScaleSetRollingUpgradesClient(subscriptionID string) VirtualMachineScaleSetRollingUpgradesClient {
	return NewVirtualMachineScaleSetRollingUpgradesClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewVirtualMachineScaleSetRollingUpgradesClientWithBaseURI creates an instance of the
// VirtualMachineScaleSetRollingUpgradesClient client.
func NewVirtualMachineScaleSetRollingUpgradesClientWithBaseURI(baseURI string, subscriptionID string) VirtualMachineScaleSetRollingUpgradesClient {
	return VirtualMachineScaleSetRollingUpgradesClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// Cancel cancels the current virtual machine scale set rolling upgrade. This method may poll for completion. Polling
// can be canceled by passing the cancel channel argument. The channel will be used to cancel polling and any
// outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. VMScaleSetName is the name of the VM scale set.
func (client VirtualMachineScaleSetRollingUpgradesClient) Cancel(resourceGroupName string, VMScaleSetName string, cancel <-chan struct{}) (<-chan OperationStatusResponse, <-chan error) {
	resultChan := make(chan OperationStatusResponse, 1)
	errChan := make(chan error, 1)
	go func() {
		var err error
		var result OperationStatusResponse
		defer func() {
			if err != nil {
				errChan <- err
			}
			resultChan <- result
			close(resultChan)
			close(errChan)
		}()
		req, err := client.CancelPreparer(resourceGroupName, VMScaleSetName, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "Cancel", nil, "Failure preparing request")
			return
		}

		resp, err := client.CancelSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "Cancel", resp, "Failure sending request")
			return
		}

		result, err = client.CancelResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "Cancel", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// CancelPreparer prepares the Cancel request.
func (client VirtualMachineScaleSetRollingUpgradesClient) CancelPreparer(resourceGroupName string, VMScaleSetName string, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"vmScaleSetName":    autorest.Encode("path", VMScaleSetName),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/rollingUpgrades/cancel", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// CancelSender sends the Cancel request. The method will close the
// http.Response Body if it receives an error.
func (client VirtualMachineScaleSetRollingUpgradesClient) CancelSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// CancelResponder handles the response to the Cancel request. The method always
// closes the http.Response Body.
func (client VirtualMachineScaleSetRollingUpgradesClient) CancelResponder(resp *http.Response) (result OperationStatusResponse, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// GetLatest gets the status of the latest virtual machine scale set rolling upgrade.
//
// resourceGroupName is the name of the resource group. VMScaleSetName is the name of the VM scale set.
func (client VirtualMachineScaleSetRollingUpgradesClient) GetLatest(resourceGroupName string, VMScaleSetName string) (result RollingUpgradeStatusInfo, err error) {
	req, err := client.GetLatestPreparer(resourceGroupName, VMScaleSetName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "GetLatest", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetLatestSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "GetLatest", resp, "Failure sending request")
		return
	}

	result, err = client.GetLatestResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "GetLatest", resp, "Failure responding to request")
	}

	return
}

// GetLatestPreparer prepares the GetLatest request.
func (client VirtualMachineScaleSetRollingUpgradesClient) GetLatestPreparer(resourceGroupName string, VMScaleSetName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"vmScaleSetName":    autorest.Encode("path", VMScaleSetName),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/rollingUpgrades/latest", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// GetLatestSender sends the GetLatest request. The method will close the
// http.Response Body if it receives an error.
func (client VirtualMachineScaleSetRollingUpgradesClient) GetLatestSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client))
}

// GetLatestResponder handles the response to the GetLatest request. The method always
// closes the http.Response Body.
func (client VirtualMachineScaleSetRollingUpgradesClient) GetLatestResponder(resp *http.Response) (result RollingUpgradeStatusInfo, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// StartOSUpgrade starts a rolling upgrade to move all virtual machine scale set instances to the latest available
// Platform Image OS version. Instances which are already running the latest available OS version are not affected.
// This method may poll for completion. Polling can be canceled by passing the cancel channel argument. The channel
// will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. VMScaleSetName is the name of the VM scale set.
func (client VirtualMachineScaleSetRollingUpgradesClient) StartOSUpgrade(resourceGroupName string, VMScaleSetName string, cancel <-chan struct{}) (<-chan OperationStatusResponse, <-chan error) {
	resultChan := make(chan OperationStatusResponse, 1)
	errChan := make(chan error, 1)
	go func() {
		var err error
		var result OperationStatusResponse
		defer func() {
			if err != nil {
				errChan <- err
			}
			resultChan <- result
			close(resultChan)
			close(errChan)
		}()
		req, err := client.StartOSUpgradePreparer(resourceGroupName, VMScaleSetName, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "StartOSUpgrade", nil, "Failure preparing request")
			return
		}

		resp, err := client.StartOSUpgradeSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "StartOSUpgrade", resp, "Failure sending request")
			return
		}

		result, err = client.StartOSUpgradeResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.VirtualMachineScaleSetRollingUpgradesClient", "StartOSUpgrade", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// StartOSUpgradePreparer prepares the StartOSUpgrade request.
func (client VirtualMachineScaleSetRollingUpgradesClient) StartOSUpgradePreparer(resourceGroupName string, VMScaleSetName string, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"vmScaleSetName":    autorest.Encode("path", VMScaleSetName),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/osRollingUpgrade", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// StartOSUpgradeSender sends the StartOSUpgrade request. The method will close the
// http.Response Body if it receives an error.
func (client VirtualMachineScaleSetRollingUpgradesClient) StartOSUpgradeSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// StartOSUpgradeResponder handles the response to the StartOSUpgrade request. The method always
// closes the http.Response Body.
func (client VirtualMachineScaleSetRollingUpgradesClient) StartOSUpgradeResponder(resp *http.Response) (result OperationStatusResponse, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
