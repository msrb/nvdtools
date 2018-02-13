"""Handle cve entries from NVD database."""

from cpe import CPE
from enum import Enum
import datetime

from collections import OrderedDict


VERSION = '4.0'


class CVE(object):
    """CVE object holding relevant attributes about the given cve."""

    # TODO: think about inheriting from dict or DataFrame for future usage


    def __init__(self, cve_id: str, references: list,
                 description: str, configurations: dict,
                 cvss, published_date: str, last_modified_date: str):
        self.cve_id = cve_id
        self.references = references or []
        self.description = description or ""
        self.configurations = configurations or {}
        self.cvss = cvss
        self.published_date = published_date
        self.last_modified_date = last_modified_date

        self.dct = self._construct_dct()

    def __str__(self):
        """Return string representation of dictionary holding object attributes."""
        return self.dct.__str__()  # TODO maybe dump to json string?

    def _construct_dct(self):
        """Construct dictionary from self attributes by NVD schema."""
        dct = OrderedDict()

        dct['cve_id'] = self.cve_id
        dct['references'] = self.references
        dct['description'] = self.description
        dct['configurations'] = self.configurations
        dct['cvss'] = self.cvss
        dct['publishedDate'] = self.published_date
        dct['lastModifiedDate'] = self.last_modified_date

        return dct

    @classmethod
    def from_dict(cls, data):
        """Initialize class from cve json dictionary."""
        date_format = '%Y-%m-%dT%H:%MZ'
        published_date = datetime.datetime.strptime(data.get('publishedDate'), date_format)
        last_modified_date = datetime.datetime.strptime(
            data.get('lastModifiedDate'), date_format)

        cve_dict = data.get('cve', {})

        # CVE ID
        cve_id = cve_dict.get('CVE_data_meta', {}).get('ID')

        # References  # TODO parse for bad url data: like `a=commit;h=....`
        references_data = cve_dict.get('references', {}).get('reference_data', [])
        references = [x.get('url') for x in references_data]

        # English description
        description_data = cve_dict.get('description', {}).get('description_data', [])
        description = ""
        for lang_description in description_data:
            if lang_description.get('lang') == 'en':
                description = lang_description.get('value', '')
                break

        # CVSSv2
        cvss = data.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')

        # Configurations  # TODO create better configurations dict - better parsing, keys, etc..
        configurations = {}
        nodes = data.get('configurations', {}).get('nodes', [])
        for node in nodes:
            cpes = node.get('cpe', [])
            for cpe in cpes:
                if cpe.get('vulnerable', True):
                    cpe_str = cpe.get('cpe22Uri')
                    if cpe_str:
                        configurations[cpe_str] = None
                    if cpe.get('versionEndIncluding') is not None:
                        configurations[cpe_str] = {'version': cpe.get('versionEndIncluding'),
                                                   'kind': 'including'}
                    elif cpe.get('versionEndExcluding') is not None:
                        configurations[cpe_str] = {'version': cpe.get('versionEndExcluding'),
                                                   'kind': 'excluding'}

        return cls(cve_id=cve_id,
                   references=references,
                   description=description,
                   configurations=configurations,
                   cvss=cvss,
                   published_date=published_date,
                   last_modified_date=last_modified_date)


class ConfigurationOperators(Enum):
    OR = 1
    AND = 2


class Configuration(object):

    def __init__(self, cpe22Uri, cpe23Uri, versionStartIncluding, versionEndIncluding, versionStartExcluding,
                 versionEndExcluding, vulnerable=False, operator=ConfigurationOperators.OR):

        self._operator = operator

        self._cpe22uri = cpe22Uri
        self._cpe23uri = cpe23Uri
        self._vulnerable = vulnerable
        self._versionStartIncluding = versionStartIncluding
        self._versionStartExcluding = versionStartExcluding
        self._versionEndIncluding = versionEndIncluding
        self._versionEndExcluding = versionEndExcluding

    @property
    def cpe22uri(self):
        return self._cpe22uri

    @property
    def cpe23uri(self):
        return self._cpe23uri

    @property
    def vulnerable(self):
        return self._vulnerable

    @property
    def versionEndIncluding(self):
        return self._versionEndIncluding

    @property
    def versionEndExcluding(self):
        return self._versionEndExcluding

    def __str__(self):
        return self.cpe23uri

    def from_dict(self, conf_dict):
        # TODO
        pass
