# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
from .kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum
import collections


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class Warcraft2Pud(KaitaiStruct):
    """Warcraft II game engine uses this format for map files. External
    maps can be edited by official Warcraft II map editor and saved in
    .pud files. Maps supplied with the game (i.e. single player
    campaign) follow the same format, but are instead embedded inside
    the game container files.
    
    There are two major versions: 0x11 (original one) and 0x13 (roughly
    corresponds to v1.33 of the game engine, although some of the
    features got limited support in v1.3).
    
    File consists of a sequence of typed sections.
    
    .. seealso::
       Source - http://cade.datamax.bg/war2x/pudspec.html
    """

    class Controller(Enum):
        computer = 1
        passive_computer = 2
        nobody = 3
        computer_ = 4
        human = 5
        rescue_passive = 6
        rescue_active = 7

    class TerrainType(Enum):
        forest = 0
        winter = 1
        wasteland = 2
        swamp = 3

    class UnitType(Enum):
        infantry = 0
        grunt = 1
        peasant = 2
        peon = 3
        ballista = 4
        catapult = 5
        knight = 6
        ogre = 7
        archer = 8
        axethrower = 9
        mage = 10
        death_knight = 11
        paladin = 12
        ogre_mage = 13
        dwarves = 14
        goblin_sapper = 15
        attack_peasant = 16
        attack_peon = 17
        ranger = 18
        berserker = 19
        alleria = 20
        teron_gorefiend = 21
        kurdan_and_sky_ree = 22
        dentarg = 23
        khadgar = 24
        grom_hellscream = 25
        human_tanker = 26
        orc_tanker = 27
        human_transport = 28
        orc_transport = 29
        elven_destroyer = 30
        troll_destroyer = 31
        battleship = 32
        juggernaught = 33
        deathwing = 35
        gnomish_submarine = 38
        giant_turtle = 39
        gnomish_flying_machine = 40
        goblin_zepplin = 41
        gryphon_rider = 42
        dragon = 43
        turalyon = 44
        eye_of_kilrogg = 45
        danath = 46
        khorgath_bladefist = 47
        cho_gall = 49
        lothar = 50
        gul_dan = 51
        uther_lightbringer = 52
        zuljin = 53
        skeleton = 55
        daemon = 56
        critter = 57
        farm = 58
        pig_farm = 59
        human_barracks = 60
        orc_barracks = 61
        church = 62
        altar_of_storms = 63
        human_scout_tower = 64
        orc_scout_tower = 65
        stables = 66
        ogre_mound = 67
        gnomish_inventor = 68
        goblin_alchemist = 69
        gryphon_aviary = 70
        dragon_roost = 71
        human_shipyard = 72
        orc_shipyard = 73
        town_hall = 74
        great_hall = 75
        elven_lumber_mill = 76
        troll_lumber_mill = 77
        human_foundry = 78
        orc_foundry = 79
        mage_tower = 80
        temple_of_the_damned = 81
        human_blacksmith = 82
        orc_blacksmith = 83
        human_refinery = 84
        orc_refinery = 85
        human_oil_well = 86
        orc_oil_well = 87
        keep = 88
        stronghold = 89
        castle = 90
        fortress = 91
        gold_mine = 92
        oil_patch = 93
        human_start = 94
        orc_start = 95
        human_guard_tower = 96
        orc_guard_tower = 97
        human_cannon_tower = 98
        orc_cannon_tower = 99
        circle_of_power = 100
        dark_portal = 101
        runestone = 102
        human_wall = 103
        orc_wall = 104
    SEQ_FIELDS = ["sections"]
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._debug = collections.defaultdict(dict)

    def _read(self):
        self._debug['sections']['start'] = self._io.pos()
        self.sections = []
        i = 0
        while not self._io.is_eof():
            if not 'arr' in self._debug['sections']:
                self._debug['sections']['arr'] = []
            self._debug['sections']['arr'].append({'start': self._io.pos()})
            _t_sections = self._root.Section(self._io, self, self._root)
            _t_sections._read()
            self.sections.append(_t_sections)
            self._debug['sections']['arr'][len(self.sections) - 1]['end'] = self._io.pos()
            i += 1

        self._debug['sections']['end'] = self._io.pos()

    class SectionStartingResource(KaitaiStruct):
        SEQ_FIELDS = ["resources_by_player"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['resources_by_player']['start'] = self._io.pos()
            self.resources_by_player = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['resources_by_player']:
                    self._debug['resources_by_player']['arr'] = []
                self._debug['resources_by_player']['arr'].append({'start': self._io.pos()})
                self.resources_by_player.append(self._io.read_u2le())
                self._debug['resources_by_player']['arr'][len(self.resources_by_player) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['resources_by_player']['end'] = self._io.pos()


    class SectionEra(KaitaiStruct):
        """Section that specifies terrain type for this map."""
        SEQ_FIELDS = ["terrain"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['terrain']['start'] = self._io.pos()
            self.terrain = KaitaiStream.resolve_enum(self._root.TerrainType, self._io.read_u2le())
            self._debug['terrain']['end'] = self._io.pos()


    class SectionVer(KaitaiStruct):
        """Section that specifies format version."""
        SEQ_FIELDS = ["version"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['version']['start'] = self._io.pos()
            self.version = self._io.read_u2le()
            self._debug['version']['end'] = self._io.pos()


    class SectionDim(KaitaiStruct):
        SEQ_FIELDS = ["x", "y"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u2le()
            self._debug['y']['end'] = self._io.pos()


    class SectionType(KaitaiStruct):
        """Section that confirms that this file is a "map file" by certain
        magic string and supplies a tag that could be used in
        multiplayer to check that all player use the same version of the
        map.
        """
        SEQ_FIELDS = ["magic", "unused", "id_tag"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.ensure_fixed_contents(b"\x57\x41\x52\x32\x20\x4D\x41\x50\x00\x00")
            self._debug['magic']['end'] = self._io.pos()
            self._debug['unused']['start'] = self._io.pos()
            self.unused = self._io.read_bytes(2)
            self._debug['unused']['end'] = self._io.pos()
            self._debug['id_tag']['start'] = self._io.pos()
            self.id_tag = self._io.read_u4le()
            self._debug['id_tag']['end'] = self._io.pos()


    class SectionUnit(KaitaiStruct):
        SEQ_FIELDS = ["units"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['units']['start'] = self._io.pos()
            self.units = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['units']:
                    self._debug['units']['arr'] = []
                self._debug['units']['arr'].append({'start': self._io.pos()})
                _t_units = self._root.Unit(self._io, self, self._root)
                _t_units._read()
                self.units.append(_t_units)
                self._debug['units']['arr'][len(self.units) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['units']['end'] = self._io.pos()


    class Section(KaitaiStruct):
        SEQ_FIELDS = ["name", "size", "body"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['name']['start'] = self._io.pos()
            self.name = (self._io.read_bytes(4)).decode(u"ASCII")
            self._debug['name']['end'] = self._io.pos()
            self._debug['size']['start'] = self._io.pos()
            self.size = self._io.read_u4le()
            self._debug['size']['end'] = self._io.pos()
            self._debug['body']['start'] = self._io.pos()
            _on = self.name
            if _on == u"SLBR":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionStartingResource(io, self, self._root)
                self.body._read()
            elif _on == u"ERAX":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionEra(io, self, self._root)
                self.body._read()
            elif _on == u"OWNR":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionOwnr(io, self, self._root)
                self.body._read()
            elif _on == u"ERA ":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionEra(io, self, self._root)
                self.body._read()
            elif _on == u"SGLD":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionStartingResource(io, self, self._root)
                self.body._read()
            elif _on == u"VER ":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionVer(io, self, self._root)
                self.body._read()
            elif _on == u"SOIL":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionStartingResource(io, self, self._root)
                self.body._read()
            elif _on == u"UNIT":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionUnit(io, self, self._root)
                self.body._read()
            elif _on == u"DIM ":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionDim(io, self, self._root)
                self.body._read()
            elif _on == u"TYPE":
                self._raw_body = self._io.read_bytes(self.size)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.SectionType(io, self, self._root)
                self.body._read()
            else:
                self.body = self._io.read_bytes(self.size)
            self._debug['body']['end'] = self._io.pos()


    class SectionOwnr(KaitaiStruct):
        """Section that specifies who controls each player."""
        SEQ_FIELDS = ["controller_by_player"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['controller_by_player']['start'] = self._io.pos()
            self.controller_by_player = []
            i = 0
            while not self._io.is_eof():
                if not 'arr' in self._debug['controller_by_player']:
                    self._debug['controller_by_player']['arr'] = []
                self._debug['controller_by_player']['arr'].append({'start': self._io.pos()})
                self.controller_by_player.append(KaitaiStream.resolve_enum(self._root.Controller, self._io.read_u1()))
                self._debug['controller_by_player']['arr'][len(self.controller_by_player) - 1]['end'] = self._io.pos()
                i += 1

            self._debug['controller_by_player']['end'] = self._io.pos()


    class Unit(KaitaiStruct):
        SEQ_FIELDS = ["x", "y", "u_type", "owner", "options"]
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._debug = collections.defaultdict(dict)

        def _read(self):
            self._debug['x']['start'] = self._io.pos()
            self.x = self._io.read_u2le()
            self._debug['x']['end'] = self._io.pos()
            self._debug['y']['start'] = self._io.pos()
            self.y = self._io.read_u2le()
            self._debug['y']['end'] = self._io.pos()
            self._debug['u_type']['start'] = self._io.pos()
            self.u_type = KaitaiStream.resolve_enum(self._root.UnitType, self._io.read_u1())
            self._debug['u_type']['end'] = self._io.pos()
            self._debug['owner']['start'] = self._io.pos()
            self.owner = self._io.read_u1()
            self._debug['owner']['end'] = self._io.pos()
            self._debug['options']['start'] = self._io.pos()
            self.options = self._io.read_u2le()
            self._debug['options']['end'] = self._io.pos()

        @property
        def resource(self):
            if hasattr(self, '_m_resource'):
                return self._m_resource if hasattr(self, '_m_resource') else None

            if  ((self.u_type == self._root.UnitType.gold_mine) or (self.u_type == self._root.UnitType.human_oil_well) or (self.u_type == self._root.UnitType.orc_oil_well) or (self.u_type == self._root.UnitType.oil_patch)) :
                self._m_resource = (self.options * 2500)

            return self._m_resource if hasattr(self, '_m_resource') else None



