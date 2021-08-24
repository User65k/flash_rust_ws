use std::{fs::Metadata, io::{Error as IoError, ErrorKind, Read, Write}, path::{Path, PathBuf}, time::SystemTime};
use bytes::{Buf, BufMut, BytesMut};
use hyper::{Body, Request, Response, StatusCode, body::aggregate};
use xml::{EmitterConfig, ParserConfig,
    common::XmlVersion,
    name::{Name, OwnedName},
    reader::{XmlEvent, EventReader, Error as XmlRError},
    writer::{EventWriter,XmlEvent as XmlWEvent, Error as XmlWError}
};
use tokio::fs::{metadata, read_dir};
use chrono::{DateTime, Utc};

pub async fn handle_propfind(mut req: Request<Body>, path: &Path, root: PathBuf, web_mount: &Path)
-> Result<Response<Body>, IoError> {

    // Get the depth
    let depth = req.headers().get("Depth")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let read = aggregate(req.body_mut()).await
        .map_err(|se|IoError::new(ErrorKind::InvalidData,se))?
        .reader();

    let xml = EventReader::new_with_config(read,
                                            ParserConfig {
                                                trim_whitespace: true,
                                                ..Default::default()
                                            });
    let mut props = Vec::new();
    if let Err(_) = parse_propfind(xml, |prop| { props.push(prop); }) {
        return Err(IoError::new(ErrorKind::InvalidData,"xml parse error"));
    }

    //log::debug!("Propfind {:?} {:?}", path, props);

    let meta = metadata(path).await?;

    let mut buf = BytesMut::new().writer();
    let mut xmlwriter = EventWriter::new_with_config(&mut buf,
                                        EmitterConfig {
                                            perform_indent: true,
                                            ..Default::default()
                                        });
    xmlwriter
        .write(XmlWEvent::StartDocument {
            version: XmlVersion::Version10,
            encoding: Some("utf-8"),
            standalone: None,
        })
        .map_err(|se|IoError::new(ErrorKind::Other,se))?;
    xmlwriter
        .write(XmlWEvent::start_element("D:multistatus").ns("D", "DAV:"))
        .map_err(|se|IoError::new(ErrorKind::Other,se))?;

    //if depth==0 && meta.is_dir(){
    //    log::info!("ls {} {:?} {:?} {:?}", depth, path, &root, web_mount);
        handle_propfind_path(&mut xmlwriter,
            path,&root, web_mount,
                &meta,
                &props)
            .map_err(|se|IoError::new(ErrorKind::Other,se))?;
    //}
    if meta.is_dir() {
        handle_propfind_path_recursive(&path, &root, web_mount, depth, &mut xmlwriter, &props).await
        .map_err(|se|IoError::new(ErrorKind::Other,se))?;
    }

    xmlwriter.write(XmlWEvent::end_element())
        .map_err(|se|IoError::new(ErrorKind::Other,se))?;

    let mut res = Response::new(Body::from(buf.into_inner().freeze()));

    *res.status_mut() = StatusCode::MULTI_STATUS;
    Ok(res)
}
fn parse_propfind<R: Read, F: FnMut(OwnedName) -> ()>(mut xml: EventReader<R>, mut f: F)
-> Result<(), XmlRError> {
    enum State {
        Start,
        PropFind,
        Prop,
        InProp,
    }

    let mut state = State::Start;

    loop {
        let event = xml.next()?;
        match state {
            State::Start => {
                match event {
                    XmlEvent::StartDocument { .. } => (),
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "propfind" => {
                        state = State::PropFind;
                    }
                    _ => return Err(IoError::new(ErrorKind::Other,"").into()),
                }
            }
            State::PropFind => {
                match event {
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "prop" => {
                        state = State::Prop;
                    }
                    _ => return Err(IoError::new(ErrorKind::Other,"").into()),
                }
            }
            State::Prop => {
                match event {
                    XmlEvent::StartElement { name, .. } => {
                        state = State::InProp;
                        f(name);
                    }
                    XmlEvent::EndElement { .. } => {
                        return Ok(());
                    }
                    _ => return Err(IoError::new(ErrorKind::Other,"").into()),
                }
            }
            State::InProp => {
                match event {
                    XmlEvent::EndElement { .. } => {
                        state = State::Prop;
                    }
                    _ => return Err(IoError::new(ErrorKind::Other,"").into()),
                }
            }
        }
    }
}
fn handle_propfind_path<W: Write>(xmlwriter: &mut EventWriter<W>,
    abs_path: &Path, root: &Path, web_mount: &Path,
    meta: &Metadata,
    props: &[OwnedName])
-> Result<(), XmlWError> {
    xmlwriter.write(XmlWEvent::start_element("D:response"))?;
    xmlwriter.write(XmlWEvent::start_element("D:href"))?;

    let url = match abs_path.strip_prefix(root).ok()
        .map(|rel_path| web_mount.join(rel_path).into_os_string())
        .and_then(|web_path| web_path.into_string().ok()) {
            Some(url) => url,
            None => return Err(IoError::new(ErrorKind::Other,"path is outside of root").into())
        };
    log::trace!("Entry: {}",url);
    xmlwriter.write(XmlWEvent::characters(&url))?;
    xmlwriter.write(XmlWEvent::end_element())?; // href

    let mut failed_props = Vec::with_capacity(props.len());
    xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
    xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
    for prop in props {
        if !handle_prop_path(xmlwriter, meta, prop.borrow())? {
            //log::warn!("prop {:?} failed", prop);
            failed_props.push(prop);
        }
    }
    xmlwriter.write(XmlWEvent::end_element())?; // prop
    xmlwriter.write(XmlWEvent::start_element("D:status"))?;
    if failed_props.len() >= props.len() {
        // If they all failed, make this a failure response and return
        xmlwriter
        .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
        xmlwriter.write(XmlWEvent::end_element())?; // status
        xmlwriter.write(XmlWEvent::end_element())?; // propstat
        xmlwriter.write(XmlWEvent::end_element())?; // response
        return Ok(());
    }
    xmlwriter.write(XmlWEvent::characters("HTTP/1.1 200 OK"))?;
    xmlwriter.write(XmlWEvent::end_element())?; // status
    xmlwriter.write(XmlWEvent::end_element())?; // propstat

    if failed_props.len() > 0 {
        // Handle the failed properties
        xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
        xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
        for prop in failed_props {
            write_client_prop(xmlwriter, prop.borrow())?;
            xmlwriter.write(XmlWEvent::end_element())?;
        }
        xmlwriter.write(XmlWEvent::end_element())?; // prop
        xmlwriter.write(XmlWEvent::start_element("D:status"))?;
        xmlwriter
        .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
        xmlwriter.write(XmlWEvent::end_element())?; // status
        xmlwriter.write(XmlWEvent::end_element())?; // propstat
    }
    xmlwriter.write(XmlWEvent::end_element())?; // response
    Ok(())
}
async fn handle_propfind_path_recursive<W: Write>(
    path: &Path, root: &Path, web_mount: &Path,
    depth: u32,
    xmlwriter: &mut EventWriter<W>,
    props: &[OwnedName])
        -> Result<(), XmlWError> {
    if depth == 0 {
        return Ok(());
    }
    let mut dir = read_dir(path).await?;
    while let Some(f) = dir.next_entry().await? {
        let path = f.path();
        let meta = match f.metadata().await {
            Ok(meta) => meta,
            Err(e) => {
                log::error!("Metadata error on {:?}. Skipping {:?}", path, e);
                continue;
            }
        };
        handle_propfind_path(xmlwriter, &path, root, web_mount, &meta, props)?;
        // Ignore errors in order to try the other files. This could fail for
        // connection reasons (not file I/O), but those should retrigger and
        // get passed up on subsequent xml writes
        let _ = handle_propfind_path_recursive(&path, root, web_mount, depth - 1, xmlwriter, props);
    }
    Ok(())
}

fn systime_to_format(time: SystemTime) -> String {
    let time: DateTime<Utc> = time.into();
    time.to_rfc3339()
}

fn handle_prop_path<W: Write>(xmlwriter: &mut EventWriter<W>,
    meta: &Metadata,
    prop: Name)
    -> Result<bool, XmlWError> {
    match (prop.namespace, prop.local_name) {
        (Some("DAV:"), "resourcetype") => {
            xmlwriter.write(XmlWEvent::start_element("D:resourcetype"))?;
            if meta.is_dir() {
                xmlwriter.write(XmlWEvent::start_element("D:collection"))?;
                xmlwriter.write(XmlWEvent::end_element())?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "creationdate") => {
            if let Ok(time) = meta.created() {
                xmlwriter.write(XmlWEvent::start_element("D:creationdate"))?;
                xmlwriter
                    .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
            Ok(false)
            }
        }
        (Some("DAV:"), "getlastmodified") => {
            if let Ok(time) = meta.modified() {
                xmlwriter
                .write(XmlWEvent::start_element("D:getlastmodified"))?;
                xmlwriter
                .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
            Ok(false)
            }
        }
        (Some("DAV:"), "getcontentlength") => {
            xmlwriter
            .write(XmlWEvent::start_element("D:getcontentlength"))?;
            xmlwriter
            .write(XmlWEvent::characters(&meta.len().to_string()))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "getcontenttype") => {
            xmlwriter
            .write(XmlWEvent::start_element("D:getcontenttype"))?;
            if meta.is_dir() {
                xmlwriter
                .write(XmlWEvent::characters("httpd/unix-directory"))?;
            } else {
            xmlwriter.write(XmlWEvent::characters("text/plain"))?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
//displayname
//source
//getcontentlanguage
//getetag
//supportedlock
//lockdiscovery
//quota-available-bytes
//quota-used-bytes
        _ => Ok(false),
    }
}

fn write_client_prop<W: Write>(xmlwriter: &mut EventWriter<W>, prop: Name)
    -> Result<(), xml::writer::Error> {
    if let Some(namespace) = prop.namespace {
        if let Some(mut prefix) = prop.prefix {
            if namespace != "DAV:" {
                // Remap the client's prefix if it overlaps with our DAV: prefix
                if prefix == "D" {
                    prefix = "U";
                }
                let newname = Name {
                    local_name: prop.local_name,
                    namespace: Some(namespace),
                    prefix: Some(prefix),//there could be more than one other NS
                };
                return xmlwriter.write(XmlWEvent::start_element(newname).ns(prefix, namespace));
            }
        }
    }
    xmlwriter.write(XmlWEvent::start_element(prop))
}
