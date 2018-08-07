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
	"github.com/Azure/go-autorest/autorest/validation"
	"net/http"
)

// SnapshotsClient is the compute Client
type SnapshotsClient struct {
	ManagementClient
}

// NewSnapshotsClient creates an instance of the SnapshotsClient client.
func NewSnapshotsClient(subscriptionID string) SnapshotsClient {
	return NewSnapshotsClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewSnapshotsClientWithBaseURI creates an instance of the SnapshotsClient client.
func NewSnapshotsClientWithBaseURI(baseURI string, subscriptionID string) SnapshotsClient {
	return SnapshotsClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// CreateOrUpdate creates or updates a snapshot. This method may poll for completion. Polling can be canceled by
// passing the cancel channel argument. The channel will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group. snapshot is snapshot object supplied in the body of the Put disk operation.
func (client SnapshotsClient) CreateOrUpdate(resourceGroupName string, snapshotName string, snapshot Snapshot, cancel <-chan struct{}) (<-chan Snapshot, <-chan error) {
	resultChan := make(chan Snapshot, 1)
	errChan := make(chan error, 1)
	if err := validation.Validate([]validation.Validation{
		{TargetValue: snapshot,
			Constraints: []validation.Constraint{{Target: "snapshot.DiskProperties", Name: validation.Null, Rule: false,
				Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.CreationData", Name: validation.Null, Rule: true,
					Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.CreationData.ImageReference", Name: validation.Null, Rule: false,
						Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.CreationData.ImageReference.ID", Name: validation.Null, Rule: true, Chain: nil}}},
					}},
					{Target: "snapshot.DiskProperties.EncryptionSettings", Name: validation.Null, Rule: false,
						Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.EncryptionSettings.DiskEncryptionKey", Name: validation.Null, Rule: false,
							Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.EncryptionSettings.DiskEncryptionKey.SourceVault", Name: validation.Null, Rule: true, Chain: nil},
								{Target: "snapshot.DiskProperties.EncryptionSettings.DiskEncryptionKey.SecretURL", Name: validation.Null, Rule: true, Chain: nil},
							}},
							{Target: "snapshot.DiskProperties.EncryptionSettings.KeyEncryptionKey", Name: validation.Null, Rule: false,
								Chain: []validation.Constraint{{Target: "snapshot.DiskProperties.EncryptionSettings.KeyEncryptionKey.SourceVault", Name: validation.Null, Rule: true, Chain: nil},
									{Target: "snapshot.DiskProperties.EncryptionSettings.KeyEncryptionKey.KeyURL", Name: validation.Null, Rule: true, Chain: nil},
								}},
						}},
				}}}}}); err != nil {
		errChan <- validation.NewErrorWithValidationError(err, "compute.SnapshotsClient", "CreateOrUpdate")
		close(errChan)
		close(resultChan)
		return resultChan, errChan
	}

	go func() {
		var err error
		var result Snapshot
		defer func() {
			if err != nil {
				errChan <- err
			}
			resultChan <- result
			close(resultChan)
			close(errChan)
		}()
		req, err := client.CreateOrUpdatePreparer(resourceGroupName, snapshotName, snapshot, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "CreateOrUpdate", nil, "Failure preparing request")
			return
		}

		resp, err := client.CreateOrUpdateSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "CreateOrUpdate", resp, "Failure sending request")
			return
		}

		result, err = client.CreateOrUpdateResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "CreateOrUpdate", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// CreateOrUpdatePreparer prepares the CreateOrUpdate request.
func (client SnapshotsClient) CreateOrUpdatePreparer(resourceGroupName string, snapshotName string, snapshot Snapshot, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsJSON(),
		autorest.AsPut(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}", pathParameters),
		autorest.WithJSON(snapshot),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// CreateOrUpdateSender sends the CreateOrUpdate request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) CreateOrUpdateSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// CreateOrUpdateResponder handles the response to the CreateOrUpdate request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) CreateOrUpdateResponder(resp *http.Response) (result Snapshot, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Delete deletes a snapshot. This method may poll for completion. Polling can be canceled by passing the cancel
// channel argument. The channel will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group.
func (client SnapshotsClient) Delete(resourceGroupName string, snapshotName string, cancel <-chan struct{}) (<-chan OperationStatusResponse, <-chan error) {
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
		req, err := client.DeletePreparer(resourceGroupName, snapshotName, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Delete", nil, "Failure preparing request")
			return
		}

		resp, err := client.DeleteSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Delete", resp, "Failure sending request")
			return
		}

		result, err = client.DeleteResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Delete", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// DeletePreparer prepares the Delete request.
func (client SnapshotsClient) DeletePreparer(resourceGroupName string, snapshotName string, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// DeleteSender sends the Delete request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) DeleteSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// DeleteResponder handles the response to the Delete request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) DeleteResponder(resp *http.Response) (result OperationStatusResponse, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted, http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Get gets information about a snapshot.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group.
func (client SnapshotsClient) Get(resourceGroupName string, snapshotName string) (result Snapshot, err error) {
	req, err := client.GetPreparer(resourceGroupName, snapshotName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Get", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Get", resp, "Failure sending request")
		return
	}

	result, err = client.GetResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Get", resp, "Failure responding to request")
	}

	return
}

// GetPreparer prepares the Get request.
func (client SnapshotsClient) GetPreparer(resourceGroupName string, snapshotName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// GetSender sends the Get request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) GetSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client))
}

// GetResponder handles the response to the Get request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) GetResponder(resp *http.Response) (result Snapshot, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// GrantAccess grants access to a snapshot. This method may poll for completion. Polling can be canceled by passing the
// cancel channel argument. The channel will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group. grantAccessData is access data object supplied in the body of the get snapshot
// access operation.
func (client SnapshotsClient) GrantAccess(resourceGroupName string, snapshotName string, grantAccessData GrantAccessData, cancel <-chan struct{}) (<-chan AccessURI, <-chan error) {
	resultChan := make(chan AccessURI, 1)
	errChan := make(chan error, 1)
	if err := validation.Validate([]validation.Validation{
		{TargetValue: grantAccessData,
			Constraints: []validation.Constraint{{Target: "grantAccessData.DurationInSeconds", Name: validation.Null, Rule: true, Chain: nil}}}}); err != nil {
		errChan <- validation.NewErrorWithValidationError(err, "compute.SnapshotsClient", "GrantAccess")
		close(errChan)
		close(resultChan)
		return resultChan, errChan
	}

	go func() {
		var err error
		var result AccessURI
		defer func() {
			if err != nil {
				errChan <- err
			}
			resultChan <- result
			close(resultChan)
			close(errChan)
		}()
		req, err := client.GrantAccessPreparer(resourceGroupName, snapshotName, grantAccessData, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "GrantAccess", nil, "Failure preparing request")
			return
		}

		resp, err := client.GrantAccessSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "GrantAccess", resp, "Failure sending request")
			return
		}

		result, err = client.GrantAccessResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "GrantAccess", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// GrantAccessPreparer prepares the GrantAccess request.
func (client SnapshotsClient) GrantAccessPreparer(resourceGroupName string, snapshotName string, grantAccessData GrantAccessData, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsJSON(),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}/beginGetAccess", pathParameters),
		autorest.WithJSON(grantAccessData),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// GrantAccessSender sends the GrantAccess request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) GrantAccessSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// GrantAccessResponder handles the response to the GrantAccess request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) GrantAccessResponder(resp *http.Response) (result AccessURI, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// List lists snapshots under a subscription.
func (client SnapshotsClient) List() (result SnapshotList, err error) {
	req, err := client.ListPreparer()
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", resp, "Failure sending request")
		return
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", resp, "Failure responding to request")
	}

	return
}

// ListPreparer prepares the List request.
func (client SnapshotsClient) ListPreparer() (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"subscriptionId": autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/providers/Microsoft.Compute/snapshots", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) ListSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) ListResponder(resp *http.Response) (result SnapshotList, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListNextResults retrieves the next set of results, if any.
func (client SnapshotsClient) ListNextResults(lastResults SnapshotList) (result SnapshotList, err error) {
	req, err := lastResults.SnapshotListPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", resp, "Failure sending next results request")
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "List", resp, "Failure responding to next results request")
	}

	return
}

// ListComplete gets all elements from the list without paging.
func (client SnapshotsClient) ListComplete(cancel <-chan struct{}) (<-chan Snapshot, <-chan error) {
	resultChan := make(chan Snapshot)
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			close(resultChan)
			close(errChan)
		}()
		list, err := client.List()
		if err != nil {
			errChan <- err
			return
		}
		if list.Value != nil {
			for _, item := range *list.Value {
				select {
				case <-cancel:
					return
				case resultChan <- item:
					// Intentionally left blank
				}
			}
		}
		for list.NextLink != nil {
			list, err = client.ListNextResults(list)
			if err != nil {
				errChan <- err
				return
			}
			if list.Value != nil {
				for _, item := range *list.Value {
					select {
					case <-cancel:
						return
					case resultChan <- item:
						// Intentionally left blank
					}
				}
			}
		}
	}()
	return resultChan, errChan
}

// ListByResourceGroup lists snapshots under a resource group.
//
// resourceGroupName is the name of the resource group.
func (client SnapshotsClient) ListByResourceGroup(resourceGroupName string) (result SnapshotList, err error) {
	req, err := client.ListByResourceGroupPreparer(resourceGroupName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListByResourceGroupSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", resp, "Failure sending request")
		return
	}

	result, err = client.ListByResourceGroupResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", resp, "Failure responding to request")
	}

	return
}

// ListByResourceGroupPreparer prepares the ListByResourceGroup request.
func (client SnapshotsClient) ListByResourceGroupPreparer(resourceGroupName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// ListByResourceGroupSender sends the ListByResourceGroup request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) ListByResourceGroupSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client))
}

// ListByResourceGroupResponder handles the response to the ListByResourceGroup request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) ListByResourceGroupResponder(resp *http.Response) (result SnapshotList, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListByResourceGroupNextResults retrieves the next set of results, if any.
func (client SnapshotsClient) ListByResourceGroupNextResults(lastResults SnapshotList) (result SnapshotList, err error) {
	req, err := lastResults.SnapshotListPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}

	resp, err := client.ListByResourceGroupSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", resp, "Failure sending next results request")
	}

	result, err = client.ListByResourceGroupResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "ListByResourceGroup", resp, "Failure responding to next results request")
	}

	return
}

// ListByResourceGroupComplete gets all elements from the list without paging.
func (client SnapshotsClient) ListByResourceGroupComplete(resourceGroupName string, cancel <-chan struct{}) (<-chan Snapshot, <-chan error) {
	resultChan := make(chan Snapshot)
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			close(resultChan)
			close(errChan)
		}()
		list, err := client.ListByResourceGroup(resourceGroupName)
		if err != nil {
			errChan <- err
			return
		}
		if list.Value != nil {
			for _, item := range *list.Value {
				select {
				case <-cancel:
					return
				case resultChan <- item:
					// Intentionally left blank
				}
			}
		}
		for list.NextLink != nil {
			list, err = client.ListByResourceGroupNextResults(list)
			if err != nil {
				errChan <- err
				return
			}
			if list.Value != nil {
				for _, item := range *list.Value {
					select {
					case <-cancel:
						return
					case resultChan <- item:
						// Intentionally left blank
					}
				}
			}
		}
	}()
	return resultChan, errChan
}

// RevokeAccess revokes access to a snapshot. This method may poll for completion. Polling can be canceled by passing
// the cancel channel argument. The channel will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group.
func (client SnapshotsClient) RevokeAccess(resourceGroupName string, snapshotName string, cancel <-chan struct{}) (<-chan OperationStatusResponse, <-chan error) {
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
		req, err := client.RevokeAccessPreparer(resourceGroupName, snapshotName, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "RevokeAccess", nil, "Failure preparing request")
			return
		}

		resp, err := client.RevokeAccessSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "RevokeAccess", resp, "Failure sending request")
			return
		}

		result, err = client.RevokeAccessResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "RevokeAccess", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// RevokeAccessPreparer prepares the RevokeAccess request.
func (client SnapshotsClient) RevokeAccessPreparer(resourceGroupName string, snapshotName string, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}/endGetAccess", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// RevokeAccessSender sends the RevokeAccess request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) RevokeAccessSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// RevokeAccessResponder handles the response to the RevokeAccess request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) RevokeAccessResponder(resp *http.Response) (result OperationStatusResponse, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Update updates (patches) a snapshot. This method may poll for completion. Polling can be canceled by passing the
// cancel channel argument. The channel will be used to cancel polling and any outstanding HTTP requests.
//
// resourceGroupName is the name of the resource group. snapshotName is the name of the snapshot within the given
// subscription and resource group. snapshot is snapshot object supplied in the body of the Patch snapshot operation.
func (client SnapshotsClient) Update(resourceGroupName string, snapshotName string, snapshot SnapshotUpdate, cancel <-chan struct{}) (<-chan Snapshot, <-chan error) {
	resultChan := make(chan Snapshot, 1)
	errChan := make(chan error, 1)
	go func() {
		var err error
		var result Snapshot
		defer func() {
			if err != nil {
				errChan <- err
			}
			resultChan <- result
			close(resultChan)
			close(errChan)
		}()
		req, err := client.UpdatePreparer(resourceGroupName, snapshotName, snapshot, cancel)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Update", nil, "Failure preparing request")
			return
		}

		resp, err := client.UpdateSender(req)
		if err != nil {
			result.Response = autorest.Response{Response: resp}
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Update", resp, "Failure sending request")
			return
		}

		result, err = client.UpdateResponder(resp)
		if err != nil {
			err = autorest.NewErrorWithError(err, "compute.SnapshotsClient", "Update", resp, "Failure responding to request")
		}
	}()
	return resultChan, errChan
}

// UpdatePreparer prepares the Update request.
func (client SnapshotsClient) UpdatePreparer(resourceGroupName string, snapshotName string, snapshot SnapshotUpdate, cancel <-chan struct{}) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"snapshotName":      autorest.Encode("path", snapshotName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-03-30"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsJSON(),
		autorest.AsPatch(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}", pathParameters),
		autorest.WithJSON(snapshot),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{Cancel: cancel})
}

// UpdateSender sends the Update request. The method will close the
// http.Response Body if it receives an error.
func (client SnapshotsClient) UpdateSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client),
		azure.DoPollForAsynchronous(client.PollingDelay))
}

// UpdateResponder handles the response to the Update request. The method always
// closes the http.Response Body.
func (client SnapshotsClient) UpdateResponder(resp *http.Response) (result Snapshot, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
