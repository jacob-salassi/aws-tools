#!/usr/bin/env python

import boto3, logging, sys, pprint

logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class filter_nvpair(dict):
	def __init__(self, name, values):
		self['Name'] = name
		self['Values'] = values


def handler(client):
	ec2_client = client

	sg_filters = [
		filter_nvpair('ip-permission.cidr', ['0.0.0.0/0']), 
		filter_nvpair('ip-permission.ipv6-cidr', ['::/0'])
	]
	groups = []
	for sg_filter in sg_filters:
		groups = groups + ec2_client.describe_security_groups(Filters=[sg_filter]).get('SecurityGroups')

	for group in groups:
		
		if_filter = filter_nvpair('group-id',[group.get('GroupId')])
		interfaces = ec2_client.describe_network_interfaces(
				Filters=[if_filter]
			).get('NetworkInterfaces')

		if len(interfaces):
			log.warning("Remediate: \n{}, \n attached to \n{} \n".format(pprint.pformat(group), pprint.pformat(interfaces)))
		else:		
			log.warning("Delete: \n{}".format(pprint.pformat(group)))


def clients_in_regions(session, service_name, override_region=None):
	regions = session.get_available_regions(service_name, partition_name='aws')

	if override_region:
		regions = [override_region]

	for region in regions:		
		client = session.client(service_name, region_name=region)
		log.debug("Returning client in region {}".format(region))
		yield client


def main():

	try:
		profile_name = sys.argv[1]
	except IndexError:
		log.fatal("AWS config profile name missing. Ex: {} myprofile".format(sys.argv[0]))
		exit()

	session = boto3.Session(profile_name=profile_name)


	service_name = 'ec2'
	for client in clients_in_regions(session=session, service_name='ec2', override_region='us-west-1'):
		handler(client)


if __name__ == "__main__":
	main()