# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from rally.plugins.openstack.context.keystone import existing_users
from tests.unit import test

CTX = "rally.plugins.openstack.context"


class ExistingUserTestCase(test.TestCase):

    @mock.patch("%s.keystone.existing_users.osclients.Clients" % CTX)
    @mock.patch("%s.keystone.existing_users.objects.Credential" % CTX)
    def test_setup(self, mock_credential, mock_clients):
        user1 = mock.MagicMock(tenant_id="1", user_id="1",
                               project_name="proj", username="usr")
        user2 = mock.MagicMock(tenant_id="1", user_id="2",
                               project_name="proj", username="usr")
        user3 = mock.MagicMock(tenant_id="2", user_id="3",
                               project_name="proj", username="usr")

        user_list = [user1, user2, user3]
        for u in user_list:
            u.get_user_id.return_value = u.user_id
            u.get_project_id.return_value = u.tenant_id

        mock_clients.return_value.keystone.side_effect = user_list

        context = {
            "task": mock.MagicMock(),
            "config": {
                "existing_users": user_list
            }
        }
        existing_users.ExistingUsers(context).setup()

        self.assertIn("users", context)
        self.assertIn("tenants", context)
        self.assertEqual(3, len(context["users"]))
        self.assertEqual(
            {
                "id": user1.user_id,
                "credential": mock_credential.return_value,
                "tenant_id": user1.tenant_id
            },
            context["users"][0]
        )
        self.assertEqual(["1", "2"], sorted(context["tenants"].keys()))
        self.assertEqual({"id": "1", "name": user1.project_name},
                         context["tenants"]["1"])
        self.assertEqual({"id": "2", "name": user3.project_name},
                         context["tenants"]["2"])

    def test_cleanup(self):
        # NOTE(boris-42): Test that cleanup is not abstract
        existing_users.ExistingUsers({"task": mock.MagicMock()}).cleanup()
