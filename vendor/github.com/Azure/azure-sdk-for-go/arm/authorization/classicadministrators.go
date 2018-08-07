package authorization

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

// ClassicAdministratorsClient is the role based access control provides you a way to apply granular level policy
// administration down to individual resources or resource groups. These operations enable you to manage role
// definitions and role assignments. A role definition describes the set of actions that can be performed on resources.
// A role assignment grants access to Azure Active Directory users.
type ClassicAdministratorsClient struct {
	ManagementClient
}

// NewClassicAdministratorsClient creates an instance of the ClassicAdministratorsClient client.
func NewClassicAdministratorsClient(subscriptionID string) ClassicAdministratorsClient {
	return NewClassicAdministratorsClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewClassicAdministratorsClientWithBaseURI creates an instance of the ClassicAdministratorsClient client.
func NewClassicAdministratorsClientWithBaseURI(baseURI string, subscriptionID string) ClassicAdministratorsClient {
	return ClassicAdministratorsClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// List gets service administrator, account administrator, and co-administrators for the subscription.
func (client ClassicAdministratorsClient) List() (result ClassicAdministratorListResult, err error) {
	req, err := client.ListPreparer()
	if err != nil {
		err = autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", resp, "Failure sending request")
		return
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", resp, "Failure responding to request")
	}

	return
}

// ListPreparer prepares the List request.
func (client ClassicAdministratorsClient) ListPreparer() (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"subscriptionId": autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2016-09-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/classicAdministrators", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client ClassicAdministratorsClient) ListSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client,
		req,
		azure.DoRetryWithRegistration(client.Client))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client ClassicAdministratorsClient) ListResponder(resp *http.Response) (result ClassicAdministratorListResult, err error) {
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
func (client ClassicAdministratorsClient) ListNextResults(lastResults ClassicAdministratorListResult) (result ClassicAdministratorListResult, err error) {
	req, err := lastResults.ClassicAdministratorListResultPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", resp, "Failure sending next results request")
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "authorization.ClassicAdministratorsClient", "List", resp, "Failure responding to next results request")
	}

	return
}

// ListComplete gets all elements from the list without paging.
func (client ClassicAdministratorsClient) ListComplete(cancel <-chan struct{}) (<-chan ClassicAdministrator, <-chan error) {
	resultChan := make(chan ClassicAdministrator)
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
