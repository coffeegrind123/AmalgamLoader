#include "ProfileMgr.h"
#include <BlackBone/src/BlackBone/Misc/Utils.h>

#define CURRENT_PROFILE L"\\LoaderCurrentProfile.xpr"

bool ProfileMgr::Save( const std::wstring& path /*= L""*/)
{
    try
    {
        auto filepath = path.empty() ? (blackbone::Utils::GetExeDirectory() + CURRENT_PROFILE) : path;

        acut::XmlDoc<wchar_t> xml;
        xml.create_document();

        for (auto& imgpath : _config.images)
            xml.append( L"LoaderConfig.imagePath" ).value( imgpath );

        xml.set( L"LoaderConfig.manualMapFlags", _config.mmapFlags );
        xml.set( L"LoaderConfig.procName",       _config.procName.c_str() );
        xml.set( L"LoaderConfig.hijack",         _config.hijack );
        xml.set( L"LoaderConfig.unlink",         _config.unlink );
        xml.set( L"LoaderConfig.erasePE",        _config.erasePE );
        xml.set( L"LoaderConfig.close",          _config.close );
        xml.set( L"LoaderConfig.krnHandle",      _config.krnHandle );
        xml.set( L"LoaderConfig.injIndef",       _config.injIndef );
        xml.set( L"LoaderConfig.processMode",    _config.processMode );
        xml.set( L"LoaderConfig.injectMode",     _config.injectMode );
        xml.set( L"LoaderConfig.delay",          _config.delay );
        xml.set( L"LoaderConfig.period",         _config.period );
        xml.set( L"LoaderConfig.skip",           _config.skipProc );
        xml.set( L"LoaderConfig.procCmdLine",    _config.procCmdLine.c_str() );
        xml.set( L"LoaderConfig.initRoutine",    _config.initRoutine.c_str() );
        xml.set( L"LoaderConfig.initArgs",       _config.initArgs.c_str() );

        xml.write_document( filepath );
        
        return true;
    }
    catch (const std::runtime_error&)
    {
        return false;
    }
}

bool ProfileMgr::Load( const std::wstring& path /*= L""*/ )
{
    try
    {
        auto filepath = path.empty() ? (blackbone::Utils::GetExeDirectory() + CURRENT_PROFILE) : path;
        if (!acut::file_exists( filepath ))
            return false;

        acut::XmlDoc<wchar_t> xml;
        xml.read_from_file( filepath );

        // Load images in a safe way
        if(xml.has( L"LoaderConfig.imagePath" ))
        {
            auto nodes = xml.all_nodes_named( L"LoaderConfig.imagePath" );
            for (auto node : nodes)
                _config.images.emplace_back( node.value() );
        }

        xml.get_if_present( L"LoaderConfig.manualMapFlags",  _config.mmapFlags );
        xml.get_if_present( L"LoaderConfig.procName",        _config.procName );
        xml.get_if_present( L"LoaderConfig.hijack",          _config.hijack );
        xml.get_if_present( L"LoaderConfig.unlink",          _config.unlink );
        xml.get_if_present( L"LoaderConfig.erasePE",         _config.erasePE );
        xml.get_if_present( L"LoaderConfig.close",           _config.close );
        xml.get_if_present( L"LoaderConfig.krnHandle",       _config.krnHandle );
        xml.get_if_present( L"LoaderConfig.injIndef",        _config.injIndef );
        xml.get_if_present( L"LoaderConfig.processMode",     _config.processMode );
        xml.get_if_present( L"LoaderConfig.injectMode",      _config.injectMode );
        xml.get_if_present( L"LoaderConfig.delay",           _config.delay );
        xml.get_if_present( L"LoaderConfig.period",          _config.period );
        xml.get_if_present( L"LoaderConfig.skip",            _config.skipProc );
        xml.get_if_present( L"LoaderConfig.procCmdLine",     _config.procCmdLine );
        xml.get_if_present( L"LoaderConfig.initRoutine",     _config.initRoutine );
        xml.get_if_present( L"LoaderConfig.initArgs",        _config.initArgs );

        return true;
    }
    catch (const std::runtime_error&)
    {
        return false;
    }
}
